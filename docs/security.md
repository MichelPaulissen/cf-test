# Security

Compiler assignments contain bounded exact-revision workflow source and public
compiler identities, never project, publication, webhook, forge, or CLI
secrets. Compiler results are treated as hostile: assignment scope and epoch,
source/manifest/environment identities, compiler/SDK identity, Wasm imports,
sizes, descriptors, ABI, and bundle digests are verified before launch.
Compiler-only policy is enforced by both node behavior and coordinator routing.

## Authority

Clusterflux separates four authority lanes:

- Client sessions for people.
- Agent public-key signatures for non-interactive workflows.
- Node public-key signatures for enrolled workers.
- Operator credentials for hosted administrative actions.

The server derives tenant, project, identity, and permission scope from the
authenticated lane. Request-body identity fields are not authority.

## Sessions and keys

Human login uses the configured identity provider and an opaque, nonce- and
PKCE-bound transaction. The CLI never accepts provider claims or authorization
codes as a session. Browser-login requests use a dedicated proxy route with
per-client rate limiting. The hosted service binds only to loopback and does not
use client-supplied forwarding headers as identity or authorization.

Enrollment grants are short-lived and single-use. Node and agent signatures bind
the canonical request body, timestamp, nonce, key fingerprint, and scope.
Forged, replayed, expired, revoked, cross-tenant, and body-modified requests
fail.

Keep `.clusterflux-state/session.json`, node private keys, agent private keys, and
operator credentials out of source control. Use protected environment files or
your secret manager.

## Execution

The coordinator does not run arbitrary native user commands. Nodes execute
commands within their reported capabilities. Linux container environments use
rootless Podman and avoid privileged defaults. Windows environments use
containerd/`nerdctl` process isolation. All supported node platforms default to
container-only command execution; native execution requires the node operator's
explicit `--dangerous-allow-native-commands` startup override.

Bundle size, canonical argument size, handle count, logs, task history, Debug
Epoch state, interchange leases, and coordinator collections are bounded. The
separate relay service bounds connections, handshakes, and byte rate. Direct
artifact body traffic is measured but has no Clusterflux byte quota or counter limit.

The official public service requires a direct path before starting or continuing an
artifact stream, so its relayed artifact-body counter is specified to remain zero.
The assist relay itself can carry small encrypted connection-establishment and path
management traffic. Hostile modified clients are not cryptographically prevented from
attempting other encrypted traffic, so the relay independently enforces active-need
admission, scoped connection/rate/burst ceilings, bounded callback workers, live
reauthorization, sustained-traffic suspension, and a global emergency ceiling.
Because the pinned upstream relay exposes body bytes as a global metric, automatic
sustained-traffic suspension is deliberately conservative: it acts only when the
sample is unambiguously attributable to one endpoint or to endpoints from one tenant.
Mixed-tenant samples never cause a suspend-all action; the global emergency switch is
an explicit operator action. Authorization, callback-worker, cache, suspension, and
connection ledgers are bounded and expired independently per scope.
Self-hosted operators own their relay bandwidth and receive relay fallback by default
when they configure the packaged relay; a coordinator with no relay URL is honestly
direct-only.

## Artifacts

Artifact links are scoped, expiring, revocable, and bound to live metadata.
Digest, size, producer, task attempt, and retaining source are checked. The
coordinator retains metadata and bounded transfer state, never artifact body
bytes. Node peers verify the remote EndpointId and scoped lease before streaming
raw bytes over Iroh; receivers verify size and SHA-256 before atomic install.

Report security issues privately using [SECURITY.md](../SECURITY.md).
