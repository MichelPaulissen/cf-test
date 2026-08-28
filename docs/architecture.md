# Architecture

The coordinator is a control plane: it validates hosted workflow manifests,
offers bounded node assignments, fences results, and launches validated Wasm.
It never runs rustc, Cargo, Podman, gVisor, or a native compiler command.
Workflow compilation and task execution use the same redelivered, explicitly
acknowledged, epoch-fenced node-work envelope. Automatic runs remain in
`waiting_for_compiler_node` until a compatible project node is online.

Clusterflux separates a control plane from execution nodes.

## Coordinator

The coordinator owns identity scope, one-active-process admission, task
placement, attempt history, Debug Epoch coordination, VFS metadata, artifact
metadata, scoped interchange leases, and peer endpoint authorization. Its async
main may park and wake without consuming node compute.

The coordinator does not execute arbitrary native commands or hosted
containers. It also does not become a durable artifact store merely because it
coordinates a download.

## Nodes

A node is an enrolled public-key identity. It reports capabilities and periodic
heartbeats. The coordinator derives whether it is live from the last accepted
heartbeat; a client-supplied "online" field is not placement authority.

Nodes resolve bundle environments, execute Wasm tasks, run native commands, and
retain artifact bytes. Each node owns one persistent, scope-bound Iroh endpoint.
The coordinator exchanges authorized endpoint advertisements and transfer
leases, but raw artifact bodies flow directly between authenticated nodes. A
node must prove the tenant, project, process, task, and key scope on every signed
request.

The public hosted relay assists hole punching, but public artifact streams start
only on a direct path. Relayed artifact body bytes are rejected and the public
relayed-body counter therefore remains zero. A self-hosted coordinator with a
configured relay permits relay fallback by default; its operator may instead
require direct paths.

## Virtual process and tasks

A Coordinator Project admits one active virtual process. The process contains:

- one coordinator-hosted async main;
- logical task instances created by that main;
- one or more attempts for each logical task;
- joins tied to the logical task, not to an individual attempt.

"FailFast" makes a terminal failure visible to the join immediately.
"AwaitOperator" keeps the join pending while an operator accepts, cancels, or
restarts the failed task. Restart creates a distinct attempt but preserves the
logical task identity.

A terminal process releases the active slot automatically. A task parked for an
operator is not terminal and continues to occupy the slot.

## Durable and live state

Projects, identities, credentials, permissions, and hosted policy records may
be stored in Postgres. Active processes, task placement, Debug Epochs, transient
VFS state, interchange leases, endpoint advertisements, and live node state are
bounded in memory and are not reconstructed as running after a coordinator
restart. Artifact bytes and partial files remain node-local.

The in-memory service keeps separate node, process, debug, interchange, and
replay registries. Node entries are keyed by enrolled identities and are removed
when credentials are revoked. Process and debug entries are retired with their
process and their retained histories have per-process and global caps.
Interchanges have a hard global capacity with terminal-entry eviction. Replay
windows have TTL and per-authority capacity limits. New live coordinator state
must join the matching registry with an explicit lifecycle cleanup or hard
capacity; adding an unconstrained top-level service collection is an
architecture violation.

Node background work runs on the node-owned Tokio runtime. Long-lived control,
artifact receiver, and artifact warm-up jobs retain join handles, observe an
explicit cancellation signal, and are joined before their owning runtime is
shut down. Fire-and-forget production background tasks are not permitted.

## Artifact data path

~~~text
node A -- metadata + signed endpoint --> coordinator <-- metadata + lease -- node B
node A <=============== direct encrypted Iroh artifact stream ===============> node B
             \---- Clusterflux relay assists path establishment ----/
~~~

On the public service, the lower relay never carries normal artifact body
bytes. On self-hosted installations, relay fallback is an operator-controlled
policy and is enabled by default when a relay is configured.

## Protocol lanes

Human clients use scoped sessions. Agents and nodes use separate signed
public-key identities. Operator actions use a separate administrative
credential. Authority comes from the authenticated lane and server-side scope,
never from identity fields in an untrusted request body.

`clusterflux-protocol` is the single owner of coordinator request and response
schemas. Production CLI, debugger, and node control requests are constructed as
those shared types and sent through `clusterflux-client::ProtocolSession`;
presentation code may keep a response as JSON after that transport boundary.
Raw JSON transport remains only for the separate hosted browser-login API.

## Crate and binary boundaries

The public runtime dependency direction is deliberately one-way: shared core
types sit below the protocol and client crates; coordinator, node, CLI, and DAP
consume those shared layers; and service-specific policy and browser backends
remain separate workspace roots. The repository architecture boundary check
evaluates Cargo metadata for all three workspaces and rejects an undeclared
runtime edge. Public workspace packages may not acquire a path dependency on
those service-specific workspaces.

Every executable target is listed explicitly in its package manifest with
Cargo binary auto-discovery disabled. Adding a new executable therefore
requires an intentional manifest and architecture-guard update; dropping a
file under `src/bin` cannot silently expand the release surface.

Product behavior is proven by compiled tests and executable journeys. A release
gate must not infer behavior by matching Rust source text or by checking that a
test function has a particular name. Static repository checks remain
appropriate for manifests, documentation, generated-file leaks, secrets, and
other properties whose authoritative evidence is the source tree itself.
