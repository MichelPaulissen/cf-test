# Self-hosting

A coordinator plus one ordinary attached node provides the full compile-and-run
experience. The coordinator package has no compiler runtime dependency. The
node release archive includes the matching compiler environment, system bundle,
SDK, toolchain, and limits. Compilation is enabled
automatically when self-check passes. Use `--system-tasks-only` on a separate
node only when the operator wants a stronger isolation boundary, not because
Clusterflux requires a second service.

Run the public coordinator and node runtime without the hosted website.

## Start a strict local coordinator

Supply one scoped bootstrap session through protected service configuration:

~~~bash
CLUSTERFLUX_SELF_HOSTED_SESSION_SECRET="$SELF_HOSTED_SESSION_SECRET" CLUSTERFLUX_SELF_HOSTED_TENANT=my-team CLUSTERFLUX_SELF_HOSTED_PROJECT=my-project CLUSTERFLUX_SELF_HOSTED_USER=me clusterflux-coordinator --listen 127.0.0.1:7999
~~~

Connect the CLI without placing the secret in a process argument:

~~~bash
printf '%s\n' "$SELF_HOSTED_SESSION_SECRET" | clusterflux auth connect-self-hosted   --coordinator 127.0.0.1:7999   --tenant my-team   --project-id my-project   --user me   --session-secret-stdin
~~~

The CLI verifies the scope before writing ".clusterflux-state/session.json". On Unix,
the session file uses mode "0600".

## Attach nodes

Use the same enrollment and worker flow described in [Nodes](nodes.md), with
"--coordinator 127.0.0.1:7999".

## Artifact relay and NAT traversal

Self-hosted installations should run `clusterflux-relay` beside the coordinator. Relay
fallback is enabled by default when a relay URL is configured, so artifacts remain
available when a direct path cannot be established. Operators can instead select
direct-only behavior; Clusterflux never silently selects an Iroh-operated relay or
address-lookup service.

Generate two independent random credentials and keep them in the protected service
environment:

~~~bash
openssl rand -hex 32
openssl rand -hex 32
~~~

The first is the private relay-callback bearer. Configure the coordinator with:

~~~text
CLUSTERFLUX_DEPLOYMENT_MODE=self-hosted
CLUSTERFLUX_IROH_RELAY_URLS=https://relay.example.com
CLUSTERFLUX_RELAY_ACCESS_CALLBACK_LISTEN=127.0.0.1:7998
CLUSTERFLUX_RELAY_ACCESS_CALLBACK_BEARER=<callback bearer>
~~~

Configure the separate relay service with the same callback bearer:

~~~text
CLUSTERFLUX_RELAY_ACCESS_MODE=callback
CLUSTERFLUX_RELAY_ACCESS_CALLBACK_URL=http://127.0.0.1:7998/internal/relay/authorize
CLUSTERFLUX_RELAY_ACCESS_CALLBACK_BEARER=<callback bearer>
CLUSTERFLUX_RELAY_BIND=127.0.0.1:3340
CLUSTERFLUX_RELAY_METRICS_BIND=127.0.0.1:9091
~~~

The callback returns a short positive grant scoped to one tenant. Callback work is
fail-closed, uses a 750 ms timeout, a 4 KiB response limit, a one-second positive cache,
32 global workers, four workers per known tenant, and only eight workers for all
first-seen EndpointIds by default. This prevents a known tenant or a flood of unknown
identities from occupying the full callback pool. Public callback URLs require HTTPS;
plain HTTP is accepted only for explicit `localhost`, `127.0.0.1`, or `::1` deployment.

The bundled [systemd service](../deploy/clusterflux-relay.service) supplies bounded
connection, memory, file-descriptor, task, and byte-rate defaults. Its 1 GiB hard
memory ceiling and 16,384-descriptor ceiling are deployment safety limits, not normal
operating targets; operators may override them to fit their node count. Put TLS in
front of port 3340, give the relay its own public DNS name, proxy WebSocket upgrades,
and expose only HTTPS to nodes. Keep the callback and metrics listeners on loopback.
Open the reverse proxy's TCP port (normally 443); do not expose ports 7998 or 9091.
Multiple comma-separated relay URLs are supported.

Coordinator artifact-transfer limits are independently configurable:

~~~text
CLUSTERFLUX_ARTIFACT_ENDPOINT_ADVERTISEMENT_TTL_SECONDS=60
CLUSTERFLUX_ARTIFACT_STREAM_TICKET_TTL_SECONDS=120
CLUSTERFLUX_ARTIFACT_ACTIVE_TRANSFER_LEASE_TTL_SECONDS=600
CLUSTERFLUX_ARTIFACT_NO_PROGRESS_TIMEOUT_SECONDS=300
CLUSTERFLUX_ARTIFACT_ABSOLUTE_TRANSFER_MAX_SECONDS=unlimited
CLUSTERFLUX_ARTIFACT_MAX_ACTIVE_TRANSFERS_PER_TENANT=128
CLUSTERFLUX_ARTIFACT_MAX_ACTIVE_TRANSFERS_PER_PROJECT=64
CLUSTERFLUX_ARTIFACT_MAX_ACTIVE_TRANSFERS_PER_PROCESS=32
CLUSTERFLUX_ARTIFACT_MAX_PROVIDER_LEASES_PER_NODE=64
CLUSTERFLUX_ARTIFACT_MAX_RECEIVER_LEASES_PER_NODE=64
CLUSTERFLUX_ARTIFACT_MAX_TRANSFER_CREATIONS_PER_TENANT_NODE_MINUTE=120
CLUSTERFLUX_ARTIFACT_MAX_PARTIAL_BYTES_PER_NODE_PROJECT=68719476736
CLUSTERFLUX_ARTIFACT_DIRECT_PATH_DEADLINE_MS=20000
CLUSTERFLUX_ARTIFACT_DIRECT_PATH_GRACE_PERIOD_MS=2000
~~~

Use `0`, `none`, or `unlimited` for the optional absolute maximum. These scoped limits
provide temporary backpressure; they are not period byte quotas. Direct artifact body
bytes have no Clusterflux byte cap.

Relay controls are also operator-owned. The packaged unit documents working defaults
for global/endpoint/tenant connections, per-connection and aggregate rates/bursts,
callback concurrency, live reauthorization, sustained-traffic detection, suspension,
and emergency disable. Self-hosted sustained detection is off unless
`CLUSTERFLUX_RELAY_SUSTAINED_BYTES_PER_SECOND` is set above zero; operators who enable
it should also set `CLUSTERFLUX_RELAY_SUSTAINED_INTERVALS` and
`CLUSTERFLUX_RELAY_SUSPENSION_SECONDS`.

The exactly pinned Iroh 1.0.3 transport keeps healthy NAT mappings active while
bounding dead connections: QUIC uses a 30-second idle timeout, 5-second keepalives,
and a 15-second per-path timeout; the relay protocol sends a health ping every 15–20
seconds and drops a client whose pong misses its 5-second deadline. Re-audit these
liveness defaults before changing the pinned Iroh version.

To forbid artifact-byte relay fallback while retaining relay-assisted hole punching,
set:

~~~text
CLUSTERFLUX_ARTIFACT_RELAY_POLICY=direct-required
~~~

To run with no relay at all, omit `CLUSTERFLUX_IROH_RELAY_URLS`. The coordinator then
starts in direct-only mode and emits a warning. `relay-fallback-allowed` is rejected
when no relay is configured. For a trusted local development installation only,
`CLUSTERFLUX_RELAY_ACCESS_MODE=shared-token` may be paired with
`CLUSTERFLUX_RELAY_SHARED_TOKEN` and the same value in the coordinator-delivered relay
access token.

Relay metrics bind to loopback by default. Watch connection admission, relayed bytes,
rate-limit pressure, and process memory. Set
`CLUSTERFLUX_RELAY_EMERGENCY_DISABLED=1` and restart the relay to fail closed during an
abuse incident. Automatic sustained-traffic enforcement suspends only a uniquely
attributable endpoint or tenant; a mixed-tenant global byte spike is reported for
operator action and never suspends every active endpoint.

## Network boundary

The native coordinator transport is plaintext and refuses non-loopback
listeners. For another machine, keep the coordinator on loopback and use an
authenticated SSH tunnel or deploy a trusted TLS reverse proxy that enforces the
same client boundary. Do not expose the native port directly.

## Administration

Project, node, process, task, log, artifact, debug, quota, and self-hosted admin
operations remain available through the public CLI/API. Authentik is one hosted
identity deployment, not a requirement for your coordinator.
