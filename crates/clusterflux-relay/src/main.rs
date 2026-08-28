use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;
use std::io::Read as _;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;
use iroh::EndpointId;
use iroh_relay::server::{
    clients::Clients, Access, AccessControl, ClientRateLimit, ClientRequest, ConnectionId, Metrics,
    RelayConfig, Server, ServerConfig,
};
use serde::Deserialize;
use tokio::sync::Semaphore;

const MAXIMUM_CALLBACK_BODY_BYTES: u64 = 4 * 1024;
const MAXIMUM_CONNECTIONS: usize = 1_000_000;
const MAXIMUM_CALLBACK_WORKERS: usize = 4_096;
const MAXIMUM_AGGREGATE_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAXIMUM_CALLBACK_TIMEOUT_MILLIS: u64 = 60_000;
const MAXIMUM_POSITIVE_CACHE_MILLIS: u64 = 5 * 60 * 1_000;
const MAXIMUM_REAUTHORIZATION_INTERVAL_MILLIS: u64 = 60_000;
const MAXIMUM_SUSTAINED_INTERVALS: u32 = 86_400;
const MAXIMUM_SUSPENSION_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Parser)]
#[command(
    name = "clusterflux-relay",
    version,
    about = "Clusterflux Iroh relay",
    after_help = "Deployment configuration is supplied through CLUSTERFLUX_RELAY_* environment variables; see docs/self-hosting.md."
)]
struct RelayArgs {}

#[derive(Debug)]
struct RelayStartupConfiguration {
    bind: SocketAddr,
    metrics: SocketAddr,
    mode: AuthorizationMode,
    maximum_global_connections: usize,
    maximum_connections_per_endpoint: usize,
    maximum_connections_per_tenant: usize,
    bytes_per_second: NonZeroU32,
    burst_bytes: NonZeroU32,
    maximum_bytes_per_second_per_endpoint: u64,
    maximum_bytes_per_second_per_tenant: u64,
    maximum_burst_bytes_per_endpoint: u64,
    maximum_burst_bytes_per_tenant: u64,
    callback_timeout: Duration,
    positive_cache_duration: Duration,
    callback_workers: usize,
    callback_workers_per_tenant: usize,
    unknown_endpoint_callback_workers: usize,
    reauthorization_interval: Duration,
    sustained_bytes_per_second: u64,
    sustained_intervals: u32,
    suspension_duration: Duration,
    emergency_disabled: bool,
}

impl RelayStartupConfiguration {
    fn from_environment() -> Result<Self, Box<dyn std::error::Error>> {
        let bind = socket_address("CLUSTERFLUX_RELAY_BIND", "0.0.0.0:3340")?;
        let metrics = socket_address("CLUSTERFLUX_RELAY_METRICS_BIND", "127.0.0.1:9091")?;
        let callback_timeout = Duration::from_millis(bounded_positive_u64(
            "CLUSTERFLUX_RELAY_CALLBACK_TIMEOUT_MS",
            750,
            MAXIMUM_CALLBACK_TIMEOUT_MILLIS,
        )?);
        let mode = authorization_mode_from_environment(callback_timeout)?;
        let maximum_global_connections = bounded_positive_usize(
            "CLUSTERFLUX_RELAY_MAX_CONNECTIONS",
            4_096,
            MAXIMUM_CONNECTIONS,
        )?;
        let maximum_connections_per_endpoint = bounded_positive_usize(
            "CLUSTERFLUX_RELAY_MAX_CONNECTIONS_PER_ENDPOINT",
            4,
            MAXIMUM_CONNECTIONS,
        )?;
        let maximum_connections_per_tenant = bounded_positive_usize(
            "CLUSTERFLUX_RELAY_MAX_CONNECTIONS_PER_TENANT",
            128,
            MAXIMUM_CONNECTIONS,
        )?;
        if maximum_connections_per_endpoint > maximum_global_connections
            || maximum_connections_per_tenant > maximum_global_connections
        {
            return Err(
                "relay scoped connection limits cannot exceed the global connection limit".into(),
            );
        }
        let bytes_per_second =
            positive_u32("CLUSTERFLUX_RELAY_BYTES_PER_SECOND", 128 * 1024 * 1024)?;
        let burst_bytes = positive_u32("CLUSTERFLUX_RELAY_BURST_BYTES", 8 * 1024 * 1024)?;
        let maximum_bytes_per_second_per_endpoint = bounded_positive_u64(
            "CLUSTERFLUX_RELAY_MAX_BYTES_PER_SECOND_PER_ENDPOINT",
            u64::from(bytes_per_second.get())
                .saturating_mul(maximum_connections_per_endpoint as u64)
                .min(MAXIMUM_AGGREGATE_BYTES),
            MAXIMUM_AGGREGATE_BYTES,
        )?;
        let maximum_bytes_per_second_per_tenant = bounded_positive_u64(
            "CLUSTERFLUX_RELAY_MAX_BYTES_PER_SECOND_PER_TENANT",
            u64::from(bytes_per_second.get())
                .saturating_mul(maximum_connections_per_tenant as u64)
                .min(MAXIMUM_AGGREGATE_BYTES),
            MAXIMUM_AGGREGATE_BYTES,
        )?;
        let maximum_burst_bytes_per_endpoint = bounded_positive_u64(
            "CLUSTERFLUX_RELAY_MAX_BURST_BYTES_PER_ENDPOINT",
            u64::from(burst_bytes.get())
                .saturating_mul(maximum_connections_per_endpoint as u64)
                .min(MAXIMUM_AGGREGATE_BYTES),
            MAXIMUM_AGGREGATE_BYTES,
        )?;
        let maximum_burst_bytes_per_tenant = bounded_positive_u64(
            "CLUSTERFLUX_RELAY_MAX_BURST_BYTES_PER_TENANT",
            u64::from(burst_bytes.get())
                .saturating_mul(maximum_connections_per_tenant as u64)
                .min(MAXIMUM_AGGREGATE_BYTES),
            MAXIMUM_AGGREGATE_BYTES,
        )?;
        if maximum_bytes_per_second_per_endpoint < u64::from(bytes_per_second.get())
            || maximum_bytes_per_second_per_tenant < u64::from(bytes_per_second.get())
            || maximum_burst_bytes_per_endpoint < u64::from(burst_bytes.get())
            || maximum_burst_bytes_per_tenant < u64::from(burst_bytes.get())
        {
            return Err(
                "relay endpoint and tenant byte ceilings must admit at least one connection".into(),
            );
        }
        let positive_cache_duration = Duration::from_millis(bounded_positive_u64(
            "CLUSTERFLUX_RELAY_POSITIVE_CACHE_MS",
            1_000,
            MAXIMUM_POSITIVE_CACHE_MILLIS,
        )?);
        let callback_workers = bounded_positive_usize(
            "CLUSTERFLUX_RELAY_CALLBACK_WORKERS",
            32,
            MAXIMUM_CALLBACK_WORKERS,
        )?;
        let callback_workers_per_tenant = bounded_positive_usize(
            "CLUSTERFLUX_RELAY_CALLBACK_WORKERS_PER_TENANT",
            callback_workers.min(4),
            MAXIMUM_CALLBACK_WORKERS,
        )?;
        let unknown_endpoint_callback_workers = bounded_positive_usize(
            "CLUSTERFLUX_RELAY_UNKNOWN_ENDPOINT_CALLBACK_WORKERS",
            callback_workers.min(8),
            MAXIMUM_CALLBACK_WORKERS,
        )?;
        if callback_workers_per_tenant > callback_workers
            || unknown_endpoint_callback_workers > callback_workers
        {
            return Err(
                "relay scoped callback-worker limits cannot exceed the global worker limit".into(),
            );
        }
        let reauthorization_interval = Duration::from_millis(bounded_positive_u64(
            "CLUSTERFLUX_RELAY_REAUTHORIZE_INTERVAL_MS",
            1_000,
            MAXIMUM_REAUTHORIZATION_INTERVAL_MILLIS,
        )?);
        let sustained_bytes_per_second = bounded_nonnegative_u64(
            "CLUSTERFLUX_RELAY_SUSTAINED_BYTES_PER_SECOND",
            0,
            MAXIMUM_AGGREGATE_BYTES,
        )?;
        let sustained_intervals = bounded_positive_u32(
            "CLUSTERFLUX_RELAY_SUSTAINED_INTERVALS",
            5,
            MAXIMUM_SUSTAINED_INTERVALS,
        )?;
        let suspension_duration = Duration::from_secs(bounded_positive_u64(
            "CLUSTERFLUX_RELAY_SUSPENSION_SECONDS",
            300,
            MAXIMUM_SUSPENSION_SECONDS,
        )?);
        let emergency_disabled = environment_flag("CLUSTERFLUX_RELAY_EMERGENCY_DISABLED")?;
        Ok(Self {
            bind,
            metrics,
            mode,
            maximum_global_connections,
            maximum_connections_per_endpoint,
            maximum_connections_per_tenant,
            bytes_per_second,
            burst_bytes,
            maximum_bytes_per_second_per_endpoint,
            maximum_bytes_per_second_per_tenant,
            maximum_burst_bytes_per_endpoint,
            maximum_burst_bytes_per_tenant,
            callback_timeout,
            positive_cache_duration,
            callback_workers,
            callback_workers_per_tenant,
            unknown_endpoint_callback_workers,
            reauthorization_interval,
            sustained_bytes_per_second,
            sustained_intervals,
            suspension_duration,
            emergency_disabled,
        })
    }
}

#[derive(Clone)]
enum AuthorizationMode {
    Callback {
        url: String,
        bearer: String,
        agent: ureq::Agent,
    },
    SharedToken(String),
}

impl fmt::Debug for AuthorizationMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Callback { .. } => formatter
                .debug_struct("Callback")
                .field("url", &"[CONFIGURED]")
                .field("bearer", &"[REDACTED]")
                .finish(),
            Self::SharedToken(_) => formatter
                .debug_tuple("SharedToken")
                .field(&"[REDACTED]")
                .finish(),
        }
    }
}

#[derive(Debug)]
struct ClusterfluxRelayAccess {
    mode: AuthorizationMode,
    emergency_disabled: bool,
    maximum_global_connections: usize,
    maximum_connections_per_endpoint: usize,
    maximum_connections_per_tenant: usize,
    bytes_per_second_per_connection: u64,
    burst_bytes_per_connection: u64,
    maximum_bytes_per_second_per_endpoint: u64,
    maximum_bytes_per_second_per_tenant: u64,
    maximum_burst_bytes_per_endpoint: u64,
    maximum_burst_bytes_per_tenant: u64,
    callback_timeout: Duration,
    positive_cache_duration: Duration,
    callback_workers: Arc<Semaphore>,
    unknown_endpoint_callback_workers: Arc<Semaphore>,
    callback_workers_per_tenant: usize,
    tenant_callback_workers: Mutex<HashMap<String, Arc<Semaphore>>>,
    positive_cache: Mutex<HashMap<EndpointId, CachedAuthorization>>,
    suspensions: Mutex<HashMap<EndpointId, Instant>>,
    tenant_suspensions: Mutex<HashMap<String, Instant>>,
    maximum_state_entries: usize,
    suspension_duration: Duration,
    connections: Mutex<ConnectionLedger>,
}

#[derive(Clone, Debug)]
struct AuthorizationGrant {
    tenant: String,
    valid_until: Instant,
}

#[derive(Clone, Debug)]
struct CachedAuthorization {
    grant: AuthorizationGrant,
}

#[derive(Clone, Debug)]
struct ConnectionReservation {
    endpoint: EndpointId,
    tenant: String,
}

#[derive(Debug, Default)]
struct ConnectionLedger {
    global: usize,
    by_endpoint: HashMap<EndpointId, HashSet<ConnectionId>>,
    by_tenant: HashMap<String, HashSet<ConnectionId>>,
    by_connection: HashMap<ConnectionId, ConnectionReservation>,
}

impl ClusterfluxRelayAccess {
    fn reserve(
        &self,
        endpoint: EndpointId,
        connection: ConnectionId,
        grant: &AuthorizationGrant,
    ) -> bool {
        let Ok(mut connections) = self.connections.lock() else {
            return false;
        };
        let endpoint_count = connections
            .by_endpoint
            .get(&endpoint)
            .map(HashSet::len)
            .unwrap_or_default();
        let tenant_count = connections
            .by_tenant
            .get(&grant.tenant)
            .map(HashSet::len)
            .unwrap_or_default();
        let next_endpoint_count = endpoint_count.saturating_add(1);
        let next_tenant_count = tenant_count.saturating_add(1);
        if connections.global >= self.maximum_global_connections
            || endpoint_count >= self.maximum_connections_per_endpoint
            || tenant_count >= self.maximum_connections_per_tenant
            || !aggregate_within_limit(
                next_endpoint_count,
                self.bytes_per_second_per_connection,
                self.maximum_bytes_per_second_per_endpoint,
            )
            || !aggregate_within_limit(
                next_tenant_count,
                self.bytes_per_second_per_connection,
                self.maximum_bytes_per_second_per_tenant,
            )
            || !aggregate_within_limit(
                next_endpoint_count,
                self.burst_bytes_per_connection,
                self.maximum_burst_bytes_per_endpoint,
            )
            || !aggregate_within_limit(
                next_tenant_count,
                self.burst_bytes_per_connection,
                self.maximum_burst_bytes_per_tenant,
            )
        {
            return false;
        }
        if connections.by_connection.contains_key(&connection) {
            return false;
        }
        let endpoint_inserted = connections
            .by_endpoint
            .entry(endpoint)
            .or_default()
            .insert(connection);
        if !endpoint_inserted {
            return false;
        }
        connections
            .by_tenant
            .entry(grant.tenant.clone())
            .or_default()
            .insert(connection);
        connections.by_connection.insert(
            connection,
            ConnectionReservation {
                endpoint,
                tenant: grant.tenant.clone(),
            },
        );
        connections.global = connections.global.saturating_add(1);
        true
    }

    fn release(&self, endpoint: EndpointId, connection: ConnectionId) {
        let Ok(mut connections) = self.connections.lock() else {
            return;
        };
        let Some(reservation) = connections.by_connection.remove(&connection) else {
            return;
        };
        if reservation.endpoint != endpoint {
            connections.by_connection.insert(connection, reservation);
            return;
        }
        remove_connection_from_index(&mut connections.by_endpoint, &endpoint, connection);
        remove_connection_from_index(&mut connections.by_tenant, &reservation.tenant, connection);
        connections.global = connections.global.saturating_sub(1);
    }

    fn active_scopes(&self) -> Vec<(EndpointId, String)> {
        let Ok(connections) = self.connections.lock() else {
            return Vec::new();
        };
        connections
            .by_endpoint
            .iter()
            .filter_map(|(endpoint, connection_ids)| {
                let connection = connection_ids.iter().next()?;
                let tenant = connections.by_connection.get(connection)?.tenant.clone();
                Some((*endpoint, tenant))
            })
            .collect()
    }

    fn tenant_for_endpoint(&self, endpoint: EndpointId) -> Option<String> {
        let connections = self.connections.lock().ok()?;
        let connection = connections.by_endpoint.get(&endpoint)?.iter().next()?;
        connections
            .by_connection
            .get(connection)
            .map(|reservation| reservation.tenant.clone())
    }

    fn active_tenants(&self) -> HashSet<String> {
        self.connections
            .lock()
            .map(|connections| connections.by_tenant.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn suspended(&self, endpoint: EndpointId) -> bool {
        let tenant = self.tenant_for_endpoint(endpoint).or_else(|| {
            self.positive_cache.lock().ok().and_then(|cache| {
                cache
                    .get(&endpoint)
                    .map(|cached| cached.grant.tenant.clone())
            })
        });
        let Ok(mut suspensions) = self.suspensions.lock() else {
            return true;
        };
        let now = Instant::now();
        suspensions.retain(|_, until| *until > now);
        if suspensions.get(&endpoint).is_some_and(|until| *until > now) {
            return true;
        }
        drop(suspensions);
        let Ok(mut tenant_suspensions) = self.tenant_suspensions.lock() else {
            return true;
        };
        tenant_suspensions.retain(|_, until| *until > now);
        tenant.is_some_and(|tenant| {
            tenant_suspensions
                .get(&tenant)
                .is_some_and(|until| *until > now)
        })
    }

    fn suspend_endpoint(&self, endpoint: EndpointId) {
        let until = Instant::now() + self.suspension_duration;
        if let Ok(mut suspensions) = self.suspensions.lock() {
            prune_deadlines(&mut suspensions, self.maximum_state_entries);
            suspensions.insert(endpoint, until);
        }
        if let Ok(mut cache) = self.positive_cache.lock() {
            cache.remove(&endpoint);
        }
    }

    fn suspend_tenant(&self, tenant: &str, endpoints: &[EndpointId]) {
        let until = Instant::now() + self.suspension_duration;
        if let Ok(mut suspensions) = self.tenant_suspensions.lock() {
            prune_deadlines(&mut suspensions, self.maximum_state_entries);
            suspensions.insert(tenant.to_owned(), until);
        }
        if let Ok(mut cache) = self.positive_cache.lock() {
            for endpoint in endpoints {
                cache.remove(endpoint);
            }
        }
    }

    async fn authorized(&self, request: &ClientRequest) -> Option<AuthorizationGrant> {
        if self.suspended(request.endpoint_id()) {
            return None;
        }
        match &self.mode {
            AuthorizationMode::SharedToken(expected) => request
                .auth_token()
                .filter(|provided| constant_time_token_eq(expected, provided))
                .map(|_| AuthorizationGrant {
                    tenant: "self-hosted-shared-token".to_owned(),
                    valid_until: Instant::now() + Duration::from_secs(60),
                }),
            AuthorizationMode::Callback { .. } => {
                self.callback_authorization(request.endpoint_id(), true)
                    .await
            }
        }
    }

    async fn reauthorize(&self, endpoint: EndpointId) -> bool {
        if self.suspended(endpoint) {
            return false;
        }
        if !matches!(&self.mode, AuthorizationMode::Callback { .. }) {
            return true;
        }
        let Some(grant) = self.callback_authorization(endpoint, false).await else {
            return false;
        };
        self.tenant_for_endpoint(endpoint)
            .is_some_and(|tenant| tenant == grant.tenant)
    }

    async fn callback_authorization(
        &self,
        endpoint: EndpointId,
        allow_cache: bool,
    ) -> Option<AuthorizationGrant> {
        let now = Instant::now();
        if allow_cache {
            if let Ok(mut cache) = self.positive_cache.lock() {
                cache.retain(|_, cached| cached.grant.valid_until > now);
                if let Some(cached) = cache.get(&endpoint) {
                    if cached.grant.valid_until > now {
                        return Some(cached.grant.clone());
                    }
                }
            }
        }
        let AuthorizationMode::Callback { url, bearer, agent } = &self.mode else {
            return None;
        };
        // First-seen EndpointIds share a deliberately smaller pool, preserving
        // callback capacity for already scoped active tenants. Once an endpoint
        // has an admitted connection, reauthorization is additionally bounded
        // by that tenant's own semaphore.
        let scope_workers = if let Some(tenant) = self.tenant_for_endpoint(endpoint) {
            let active_tenants = self.active_tenants();
            let mut workers = self.tenant_callback_workers.lock().ok()?;
            workers.retain(|candidate, _| active_tenants.contains(candidate));
            if !workers.contains_key(&tenant) && workers.len() >= self.maximum_state_entries {
                return None;
            }
            Arc::clone(
                workers
                    .entry(tenant)
                    .or_insert_with(|| Arc::new(Semaphore::new(self.callback_workers_per_tenant))),
            )
        } else {
            Arc::clone(&self.unknown_endpoint_callback_workers)
        };
        let global_workers = Arc::clone(&self.callback_workers);
        let (scope_permit, global_permit) =
            tokio::time::timeout(self.callback_timeout, async move {
                let scope_permit = scope_workers.acquire_owned().await.ok()?;
                let global_permit = global_workers.acquire_owned().await.ok()?;
                Some((scope_permit, global_permit))
            })
            .await
            .ok()??;
        let url = url.clone();
        let bearer = bearer.clone();
        let agent = agent.clone();
        let endpoint_text = endpoint.to_string();
        let default_cache_duration = self.positive_cache_duration;
        let response = tokio::time::timeout(
            self.callback_timeout,
            tokio::task::spawn_blocking(move || {
                let _scope_permit = scope_permit;
                let _global_permit = global_permit;
                let authorization = format!("Bearer {bearer}");
                let response = agent
                    .post(&url)
                    .set("Authorization", &authorization)
                    .set("X-Iroh-Endpoint-Id", &endpoint_text)
                    .call()
                    .ok()?;
                if response.status() != 200
                    || response
                        .header("Content-Length")
                        .and_then(|value| value.parse::<u64>().ok())
                        .is_some_and(|length| length > MAXIMUM_CALLBACK_BODY_BYTES)
                {
                    return None;
                }
                let mut body = String::new();
                response
                    .into_reader()
                    .take(MAXIMUM_CALLBACK_BODY_BYTES + 1)
                    .read_to_string(&mut body)
                    .ok()?;
                if body.len() as u64 > MAXIMUM_CALLBACK_BODY_BYTES {
                    return None;
                }
                parse_callback_authorization(&body, default_cache_duration)
            }),
        )
        .await
        .ok()?
        .ok()??;
        if response.valid_until <= Instant::now() {
            return None;
        }
        if let Ok(mut cache) = self.positive_cache.lock() {
            cache.retain(|_, cached| cached.grant.valid_until > Instant::now());
            while cache.len() >= self.maximum_state_entries {
                let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, cached)| cached.grant.valid_until)
                    .map(|(endpoint, _)| *endpoint)
                else {
                    break;
                };
                cache.remove(&oldest);
            }
            cache.insert(
                endpoint,
                CachedAuthorization {
                    grant: response.clone(),
                },
            );
        }
        Some(response)
    }
}

fn prune_deadlines<K: Eq + Hash + Clone>(deadlines: &mut HashMap<K, Instant>, capacity: usize) {
    let now = Instant::now();
    deadlines.retain(|_, until| *until > now);
    while deadlines.len() >= capacity.max(1) {
        let Some(oldest) = deadlines
            .iter()
            .min_by_key(|(_, until)| **until)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        deadlines.remove(&oldest);
    }
}

impl AccessControl for ClusterfluxRelayAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        if self.emergency_disabled {
            return Access::Deny { reason: None };
        }
        let Some(grant) = self.authorized(request).await else {
            return Access::Deny { reason: None };
        };
        if !self.reserve(request.endpoint_id(), request.connection_id(), &grant) {
            return Access::Deny { reason: None };
        }
        Access::Allow
    }

    fn on_disconnect(&self, endpoint_id: EndpointId, connection_id: ConnectionId) {
        self.release(endpoint_id, connection_id);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _args = RelayArgs::parse();
    let configuration = RelayStartupConfiguration::from_environment()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(configuration))
}

async fn run(configuration: RelayStartupConfiguration) -> Result<(), Box<dyn std::error::Error>> {
    let RelayStartupConfiguration {
        bind,
        metrics,
        mode,
        maximum_global_connections,
        maximum_connections_per_endpoint,
        maximum_connections_per_tenant,
        bytes_per_second,
        burst_bytes,
        maximum_bytes_per_second_per_endpoint,
        maximum_bytes_per_second_per_tenant,
        maximum_burst_bytes_per_endpoint,
        maximum_burst_bytes_per_tenant,
        callback_timeout,
        positive_cache_duration,
        callback_workers,
        callback_workers_per_tenant,
        unknown_endpoint_callback_workers,
        reauthorization_interval,
        sustained_bytes_per_second,
        sustained_intervals,
        suspension_duration,
        emergency_disabled,
    } = configuration;
    let access = Arc::new(ClusterfluxRelayAccess {
        mode,
        emergency_disabled,
        maximum_global_connections,
        maximum_connections_per_endpoint,
        maximum_connections_per_tenant,
        bytes_per_second_per_connection: u64::from(bytes_per_second.get()),
        burst_bytes_per_connection: u64::from(burst_bytes.get()),
        maximum_bytes_per_second_per_endpoint,
        maximum_bytes_per_second_per_tenant,
        maximum_burst_bytes_per_endpoint,
        maximum_burst_bytes_per_tenant,
        callback_timeout,
        positive_cache_duration,
        callback_workers: Arc::new(Semaphore::new(callback_workers)),
        unknown_endpoint_callback_workers: Arc::new(Semaphore::new(
            unknown_endpoint_callback_workers,
        )),
        callback_workers_per_tenant,
        tenant_callback_workers: Mutex::new(HashMap::new()),
        positive_cache: Mutex::new(HashMap::new()),
        suspensions: Mutex::new(HashMap::new()),
        tenant_suspensions: Mutex::new(HashMap::new()),
        maximum_state_entries: maximum_global_connections.saturating_mul(2).max(1),
        suspension_duration,
        connections: Mutex::new(ConnectionLedger::default()),
    });
    let mut relay = RelayConfig::new(bind);
    let mut rate_limit = ClientRateLimit::new(bytes_per_second);
    rate_limit.max_burst_bytes = Some(burst_bytes);
    relay.limits.client_rx = Some(rate_limit);
    relay.key_cache_capacity = Some(maximum_global_connections.saturating_mul(2));
    relay.access = access.clone();
    let mut configuration = ServerConfig::default();
    configuration.relay = Some(relay);
    configuration.metrics_addr = Some(metrics);
    let server = Server::spawn(configuration).await?;
    let clients = server
        .relay_service()
        .ok_or("relay service was not started")?
        .clients()
        .clone();
    let policy_monitor = tokio::spawn(monitor_relay_policy(
        Arc::clone(&access),
        clients,
        Arc::clone(&server.metrics().server),
        reauthorization_interval,
        sustained_bytes_per_second,
        sustained_intervals,
    ));
    println!(
        "clusterflux-relay ready bind={bind} metrics={metrics} max_connections={maximum_global_connections} max_per_endpoint={maximum_connections_per_endpoint} max_per_tenant={maximum_connections_per_tenant} bytes_per_second={}",
        bytes_per_second.get()
    );
    tokio::signal::ctrl_c().await?;
    policy_monitor.abort();
    server.shutdown().await?;
    Ok(())
}

fn authorization_mode_from_environment(timeout: Duration) -> Result<AuthorizationMode, String> {
    match environment("CLUSTERFLUX_RELAY_ACCESS_MODE", "callback")?.as_str() {
        "callback" => {
            let url = required_environment("CLUSTERFLUX_RELAY_ACCESS_CALLBACK_URL")?;
            validate_callback_url(&url)?;
            let bearer = required_token_environment("CLUSTERFLUX_RELAY_ACCESS_CALLBACK_BEARER")?;
            let agent = ureq::AgentBuilder::new()
                .timeout_connect(timeout)
                .timeout_read(timeout)
                .timeout_write(timeout)
                .redirects(0)
                .build();
            Ok(AuthorizationMode::Callback { url, bearer, agent })
        }
        "shared-token" => Ok(AuthorizationMode::SharedToken(required_token_environment(
            "CLUSTERFLUX_RELAY_SHARED_TOKEN",
        )?)),
        value => Err(format!(
            "CLUSTERFLUX_RELAY_ACCESS_MODE must be callback or shared-token; got {value}"
        )),
    }
}

fn environment(name: &str, default: &str) -> Result<String, String> {
    match std::env::var(name) {
        Ok(value) => Ok(value),
        Err(std::env::VarError::NotPresent) => Ok(default.to_owned()),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} must contain valid Unicode")),
    }
}

fn socket_address(name: &str, default: &str) -> Result<SocketAddr, String> {
    environment(name, default)?
        .parse::<SocketAddr>()
        .map_err(|error| format!("{name} is invalid: {error}"))
}

fn required_environment(name: &str) -> Result<String, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) | Err(std::env::VarError::NotPresent) => {
            Err(format!("{name} must be configured and non-empty"))
        }
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} must contain valid Unicode")),
    }
}

fn required_token_environment(name: &str) -> Result<String, String> {
    let value = required_environment(name)?;
    if value.len() > 4_096 || value.chars().any(char::is_control) {
        return Err(format!(
            "{name} must be at most 4096 bytes without control characters"
        ));
    }
    Ok(value)
}

fn environment_flag(name: &str) -> Result<bool, String> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} must contain valid Unicode")),
        Ok(value) => match value.as_str() {
            "0" | "false" => Ok(false),
            "1" | "true" => Ok(true),
            _ => Err(format!("{name} must be one of 0, 1, false, or true")),
        },
    }
}

fn bounded_positive_usize(name: &str, default: usize, maximum: usize) -> Result<usize, String> {
    let configured = environment(name, &default.to_string())?;
    parse_bounded_positive_usize(name, &configured, maximum)
}

fn parse_bounded_positive_usize(
    name: &str,
    configured: &str,
    maximum: usize,
) -> Result<usize, String> {
    let value = configured
        .parse::<usize>()
        .map_err(|error| format!("{name} is invalid: {error}"))?;
    if !(1..=maximum).contains(&value) {
        return Err(format!("{name} must be between 1 and {maximum}"));
    }
    Ok(value)
}

fn positive_u32(name: &str, default: u32) -> Result<NonZeroU32, String> {
    let value = environment(name, &default.to_string())?
        .parse::<u32>()
        .map_err(|error| format!("{name} is invalid: {error}"))?;
    NonZeroU32::new(value).ok_or_else(|| format!("{name} must be positive"))
}

fn bounded_positive_u32(name: &str, default: u32, maximum: u32) -> Result<u32, String> {
    let configured = environment(name, &default.to_string())?;
    parse_bounded_positive_u32(name, &configured, maximum)
}

fn parse_bounded_positive_u32(name: &str, configured: &str, maximum: u32) -> Result<u32, String> {
    let value = configured
        .parse::<u32>()
        .map_err(|error| format!("{name} is invalid: {error}"))?;
    if !(1..=maximum).contains(&value) {
        return Err(format!("{name} must be between 1 and {maximum}"));
    }
    Ok(value)
}

fn bounded_positive_u64(name: &str, default: u64, maximum: u64) -> Result<u64, String> {
    let configured = environment(name, &default.to_string())?;
    parse_bounded_positive_u64(name, &configured, maximum)
}

fn parse_bounded_positive_u64(name: &str, configured: &str, maximum: u64) -> Result<u64, String> {
    let value = configured
        .parse::<u64>()
        .map_err(|error| format!("{name} is invalid: {error}"))?;
    if !(1..=maximum).contains(&value) {
        return Err(format!("{name} must be between 1 and {maximum}"));
    }
    Ok(value)
}

fn bounded_nonnegative_u64(name: &str, default: u64, maximum: u64) -> Result<u64, String> {
    let configured = environment(name, &default.to_string())?;
    parse_bounded_nonnegative_u64(name, &configured, maximum)
}

fn parse_bounded_nonnegative_u64(
    name: &str,
    configured: &str,
    maximum: u64,
) -> Result<u64, String> {
    let value = configured
        .parse::<u64>()
        .map_err(|error| format!("{name} is invalid: {error}"))?;
    if value > maximum {
        return Err(format!("{name} must not exceed {maximum}"));
    }
    Ok(value)
}

fn aggregate_within_limit(count: usize, per_connection: u64, maximum: u64) -> bool {
    (count as u64).saturating_mul(per_connection) <= maximum
}

fn remove_connection_from_index<K: std::hash::Hash + Eq>(
    index: &mut HashMap<K, HashSet<ConnectionId>>,
    key: &K,
    connection: ConnectionId,
) {
    let empty = index.get_mut(key).is_some_and(|connections| {
        connections.remove(&connection);
        connections.is_empty()
    });
    if empty {
        index.remove(key);
    }
}

#[derive(Debug, Deserialize)]
struct CallbackAuthorizationResponse {
    allowed: bool,
    tenant: Option<String>,
    valid_for_ms: Option<u64>,
}

fn parse_callback_authorization(
    body: &str,
    maximum_cache_duration: Duration,
) -> Option<AuthorizationGrant> {
    if body.trim() == "true" {
        return Some(AuthorizationGrant {
            tenant: "legacy-callback".to_owned(),
            valid_until: Instant::now() + maximum_cache_duration,
        });
    }
    let response = serde_json::from_str::<CallbackAuthorizationResponse>(body).ok()?;
    if !response.allowed {
        return None;
    }
    let tenant = response.tenant?.trim().to_owned();
    if tenant.is_empty() || tenant.len() > 255 || tenant.chars().any(char::is_control) {
        return None;
    }
    let advertised = Duration::from_millis(response.valid_for_ms.unwrap_or_default());
    let duration = advertised.min(maximum_cache_duration);
    if duration.is_zero() {
        return None;
    }
    Some(AuthorizationGrant {
        tenant,
        valid_until: Instant::now() + duration,
    })
}

fn validate_callback_url(value: &str) -> Result<(), String> {
    if value.len() > 2_048 || value.chars().any(char::is_control) {
        return Err(
            "CLUSTERFLUX_RELAY_ACCESS_CALLBACK_URL must be at most 2048 bytes without control characters"
                .to_owned(),
        );
    }
    let url = url::Url::parse(value)
        .map_err(|error| format!("CLUSTERFLUX_RELAY_ACCESS_CALLBACK_URL is invalid: {error}"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "CLUSTERFLUX_RELAY_ACCESS_CALLBACK_URL must not contain credentials, query, or fragment"
                .to_owned(),
        );
    }
    let explicit_loopback = match url.host() {
        Some(url::Host::Ipv4(address)) => address == std::net::Ipv4Addr::LOCALHOST,
        Some(url::Host::Ipv6(address)) => address == std::net::Ipv6Addr::LOCALHOST,
        Some(url::Host::Domain(domain)) => domain == "localhost",
        None => false,
    };
    match url.scheme() {
        "https" => Ok(()),
        "http" if explicit_loopback => Ok(()),
        "http" => Err(
            "CLUSTERFLUX_RELAY_ACCESS_CALLBACK_URL permits HTTP only for an explicit loopback host"
                .to_owned(),
        ),
        _ => Err(
            "CLUSTERFLUX_RELAY_ACCESS_CALLBACK_URL must use HTTPS or explicit loopback HTTP"
                .to_owned(),
        ),
    }
}

async fn monitor_relay_policy(
    access: Arc<ClusterfluxRelayAccess>,
    clients: Clients,
    metrics: Arc<Metrics>,
    interval: Duration,
    sustained_bytes_per_second: u64,
    sustained_intervals: u32,
) {
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut previous_bytes = metrics.bytes_recv.get();
    let mut previous_sample = Instant::now();
    let mut sustained =
        SustainedTrafficDetector::new(sustained_bytes_per_second, sustained_intervals);
    loop {
        timer.tick().await;
        let scopes = access.active_scopes();
        let endpoints = scopes
            .iter()
            .map(|(endpoint, _)| *endpoint)
            .collect::<Vec<_>>();
        let mut checks = tokio::task::JoinSet::new();
        for endpoint in endpoints.iter().copied() {
            let access = Arc::clone(&access);
            checks.spawn(async move { (endpoint, access.reauthorize(endpoint).await) });
        }
        while let Some(result) = checks.join_next().await {
            if let Ok((endpoint, false)) = result {
                clients.disconnect(endpoint, None);
            }
        }

        let now = Instant::now();
        let current_bytes = metrics.bytes_recv.get();
        let elapsed_millis = now
            .saturating_duration_since(previous_sample)
            .as_millis()
            .max(1) as u64;
        let observed_per_second = current_bytes
            .saturating_sub(previous_bytes)
            .saturating_mul(1_000)
            / elapsed_millis;
        previous_bytes = current_bytes;
        previous_sample = now;
        if sustained.observe(observed_per_second, !endpoints.is_empty()) {
            // The upstream relay metric is global. Enforce automatically only
            // when that delta is unambiguously attributable to one endpoint or
            // one tenant. Mixed-tenant traffic remains an operator-visible
            // global emergency condition; it never suspends innocent scopes.
            match attributable_abuse_scope(&scopes) {
                Some(AbuseScope::Endpoint(endpoint)) => {
                    access.suspend_endpoint(endpoint);
                    clients.disconnect(endpoint, None);
                }
                Some(AbuseScope::Tenant { tenant, endpoints }) => {
                    access.suspend_tenant(&tenant, &endpoints);
                    for endpoint in endpoints {
                        clients.disconnect(endpoint, None);
                    }
                }
                None => {}
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AbuseScope {
    Endpoint(EndpointId),
    Tenant {
        tenant: String,
        endpoints: Vec<EndpointId>,
    },
}

fn attributable_abuse_scope(scopes: &[(EndpointId, String)]) -> Option<AbuseScope> {
    if scopes.len() == 1 {
        return Some(AbuseScope::Endpoint(scopes[0].0));
    }
    let tenant = scopes.first()?.1.clone();
    scopes
        .iter()
        .all(|(_, candidate)| candidate == &tenant)
        .then(|| AbuseScope::Tenant {
            tenant,
            endpoints: scopes.iter().map(|(endpoint, _)| *endpoint).collect(),
        })
}

#[derive(Debug)]
struct SustainedTrafficDetector {
    bytes_per_second_threshold: u64,
    required_intervals: u32,
    consecutive_intervals: u32,
}

impl SustainedTrafficDetector {
    fn new(bytes_per_second_threshold: u64, required_intervals: u32) -> Self {
        Self {
            bytes_per_second_threshold,
            required_intervals,
            consecutive_intervals: 0,
        }
    }

    fn observe(&mut self, bytes_per_second: u64, has_active_endpoints: bool) -> bool {
        if self.bytes_per_second_threshold > 0
            && has_active_endpoints
            && bytes_per_second > self.bytes_per_second_threshold
        {
            self.consecutive_intervals = self.consecutive_intervals.saturating_add(1);
        } else {
            self.consecutive_intervals = 0;
        }
        if self.consecutive_intervals >= self.required_intervals {
            self.consecutive_intervals = 0;
            true
        } else {
            false
        }
    }
}

fn constant_time_token_eq(expected: &str, provided: &str) -> bool {
    let maximum = expected.len().max(provided.len());
    let mut difference = expected.len() ^ provided.len();
    for index in 0..maximum {
        difference |= usize::from(
            expected.as_bytes().get(index).copied().unwrap_or_default()
                ^ provided.as_bytes().get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    #[test]
    fn clap_configuration_rejects_unknown_flags() {
        assert!(RelayArgs::try_parse_from(["clusterflux-relay"]).is_ok());
        assert!(RelayArgs::try_parse_from(["clusterflux-relay", "--unknown"]).is_err());
    }

    #[test]
    fn token_comparison_checks_content_and_length() {
        assert!(constant_time_token_eq("secret", "secret"));
        assert!(!constant_time_token_eq("secret", "secreu"));
        assert!(!constant_time_token_eq("secret", "secret-longer"));
    }

    #[test]
    fn nonzero_rate_limits_are_enforced_by_type() {
        assert!(NonZeroU32::new(0).is_none());
        assert!(NonZeroU32::new(1).is_some());
    }

    #[test]
    fn aggregate_rate_limit_is_a_hard_connection_admission_bound() {
        assert!(aggregate_within_limit(2, 256 * 1024, 512 * 1024));
        assert!(!aggregate_within_limit(3, 256 * 1024, 512 * 1024));
    }

    #[test]
    fn sustained_assist_traffic_requires_consecutive_samples_and_then_suspends() {
        let mut detector = SustainedTrafficDetector::new(128 * 1024, 3);
        assert!(!detector.observe(129 * 1024, true));
        assert!(!detector.observe(129 * 1024, true));
        assert!(!detector.observe(1, true));
        assert!(!detector.observe(129 * 1024, true));
        assert!(!detector.observe(129 * 1024, true));
        assert!(detector.observe(129 * 1024, true));
        assert!(!detector.observe(u64::MAX, false));
    }

    #[test]
    fn global_metric_is_enforced_only_at_an_unambiguous_scope() {
        let endpoint_a = SecretKey::generate().public();
        let endpoint_b = SecretKey::generate().public();
        assert_eq!(
            attributable_abuse_scope(&[(endpoint_a, "tenant-a".to_owned())]),
            Some(AbuseScope::Endpoint(endpoint_a))
        );
        assert_eq!(
            attributable_abuse_scope(&[
                (endpoint_a, "tenant-a".to_owned()),
                (endpoint_b, "tenant-a".to_owned()),
            ]),
            Some(AbuseScope::Tenant {
                tenant: "tenant-a".to_owned(),
                endpoints: vec![endpoint_a, endpoint_b],
            })
        );
        assert_eq!(
            attributable_abuse_scope(&[
                (endpoint_a, "tenant-a".to_owned()),
                (endpoint_b, "tenant-b".to_owned()),
            ]),
            None,
            "mixed-tenant traffic must not globally suspend both tenants"
        );
    }

    #[test]
    fn scoped_deadline_maps_prune_expired_and_bound_live_entries() {
        let now = Instant::now();
        let mut deadlines = HashMap::from([
            ("expired".to_owned(), now - Duration::from_secs(1)),
            ("first".to_owned(), now + Duration::from_secs(1)),
            ("second".to_owned(), now + Duration::from_secs(2)),
        ]);
        prune_deadlines(&mut deadlines, 2);
        assert_eq!(deadlines.len(), 1);
        assert!(!deadlines.contains_key("expired"));
        assert!(deadlines.contains_key("second"));
    }

    #[test]
    fn callback_worker_scopes_reserve_capacity_for_known_tenants() {
        let global = Arc::new(Semaphore::new(32));
        let unknown = Arc::new(Semaphore::new(8));
        let tenant = Arc::new(Semaphore::new(4));
        let _unknown_scope = Arc::clone(&unknown).try_acquire_many_owned(8).unwrap();
        let _unknown_global = Arc::clone(&global).try_acquire_many_owned(8).unwrap();
        assert!(Arc::clone(&unknown).try_acquire_owned().is_err());
        assert_eq!(global.available_permits(), 24);
        let _known_scope = Arc::clone(&tenant).try_acquire_owned().unwrap();
        let _known_global = Arc::clone(&global).try_acquire_owned().unwrap();
        assert_eq!(global.available_permits(), 23);
    }

    #[test]
    fn callback_grant_requires_a_bounded_tenant_scope() {
        let now = Instant::now();
        let grant = parse_callback_authorization(
            r#"{"allowed":true,"tenant":"tenant-a","valid_for_ms":5000}"#,
            Duration::from_secs(1),
        )
        .expect("valid scoped grant");
        assert_eq!(grant.tenant, "tenant-a");
        assert!(grant.valid_until > now);
        assert!(grant.valid_until <= now + Duration::from_millis(1_100));
        assert!(parse_callback_authorization(
            r#"{"allowed":false,"tenant":"tenant-a","valid_for_ms":1000}"#,
            Duration::from_secs(1),
        )
        .is_none());
        assert!(parse_callback_authorization(
            r#"{"allowed":true,"valid_for_ms":1000}"#,
            Duration::from_secs(1),
        )
        .is_none());
    }

    #[test]
    fn callback_transport_rejects_public_plaintext() {
        assert!(validate_callback_url("https://policy.example/internal/relay/authorize").is_ok());
        assert!(validate_callback_url("http://127.0.0.1:7998/internal/relay/authorize").is_ok());
        assert!(validate_callback_url("http://[::1]:7998/internal/relay/authorize").is_ok());
        assert!(validate_callback_url("http://policy.example/internal/relay/authorize").is_err());
        assert!(validate_callback_url(
            "https://operator:secret@policy.example/internal/relay/authorize"
        )
        .is_err());
        assert!(validate_callback_url(
            "https://policy.example/internal/relay/authorize?token=secret"
        )
        .is_err());
    }

    #[test]
    fn startup_limit_parsers_reject_zero_and_effectively_unbounded_values() {
        assert!(parse_bounded_positive_usize("limit", "0", 10).is_err());
        assert!(parse_bounded_positive_usize("limit", &usize::MAX.to_string(), 10).is_err());
        assert!(parse_bounded_positive_u32("limit", "0", 10).is_err());
        assert!(parse_bounded_positive_u32("limit", &u32::MAX.to_string(), 10).is_err());
        assert!(parse_bounded_positive_u64("limit", "0", 10).is_err());
        assert!(parse_bounded_positive_u64("limit", &u64::MAX.to_string(), 10).is_err());
        assert_eq!(parse_bounded_nonnegative_u64("limit", "0", 10), Ok(0));
        assert!(parse_bounded_nonnegative_u64("limit", &u64::MAX.to_string(), 10).is_err());
    }

    #[test]
    fn authorization_debug_output_redacts_bearers() {
        let mode = AuthorizationMode::SharedToken("never-print-this".to_owned());
        let debug = format!("{mode:?}");
        assert!(!debug.contains("never-print-this"));
        assert!(debug.contains("REDACTED"));
    }
}
