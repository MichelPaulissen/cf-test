# Artifacts

Clusterflux separates artifact metadata from artifact bytes.

## Publish metadata

`flush()` makes a VFS artifact visible to downstream tasks and records its
digest, size, producer task and attempt, and retaining locations. It does not
upload bytes to the coordinator by default.

Your node retains artifact bytes on a best-effort basis. If every retaining node
is lost, stale, revoked, or garbage-collects the bytes, the artifact is
unavailable. Clusterflux reports that state instead of inventing durable
storage.

## Automatic node interchange

Tasks start as soon as their Wasm instance and environment are ready. Missing artifact
bytes do not delay startup: the node begins one background warm-up per tenant, project,
and digest. Consumers on that node join the same in-progress transfer. A task that never
uses its handle can finish even if speculative warm-up fails; `materialize()` or `open()`
waits for the bytes and returns a typed artifact error only when the task actually needs
them. Task/process cancellation, worker shutdown, or explicit release promptly cancels
an otherwise-unused warm-up.

When a task depends on an artifact retained by another node, the destination obtains a
short-lived, scope-bound stream-start ticket and the exact authorized Iroh peer address
from the coordinator. A separate renewable active-transfer lease keeps the source pin
and receiver partial alive while progress or an allowed wait state is reported. The
default stream ticket is two minutes; active transfers can run for hours. Stalls expire
after the configured no-progress timeout, and self-hosters may configure or disable an
absolute maximum.

Raw bytes move directly between authenticated node endpoints. The coordinator does not
carry the artifact body. The receiver resumes a bounded partial file, verifies the
expected size and SHA-256 digest, atomically installs it, and only then reports the new
retaining location.

The public Clusterflux service uses its relay only to assist connection establishment
and requires the artifact stream to be on a direct path. A path that becomes relayed is
cancelled and can be resumed later; normal artifact body bytes are not sent through the
public relay. A self-hosted coordinator allows relay fallback by default when its
administrator has configured a relay.

## Release retention early

Workflows that no longer need the producer's process-level retention can consume the
handle with:

~~~rust
artifact.release().await?;
~~~

Release is idempotent at the coordinator. It removes only that process-retention reason;
active task consumers, transfers, downloads, restart checkpoints, and explicit holds
remain safe. Process termination automatically releases any process holds left behind.
A later use of an explicitly released handle returns a typed `ArtifactReleased` error
when no valid retention need remains. Release is metadata-only: it is available both to
the capless coordinator-hosted main and to node-hosted tasks, and does not require a
filesystem or VFS capability.

## Move bytes explicitly

Use `sync()` or an explicit export when you need another node or your own storage
system to hold the bytes. Explicit node export uses the same verified interchange
engine as task prefetch. The command returns the tracked transfer before body bytes
finish, while the receiver performs the transfer in its background engine. Same-node
reuse avoids a network transfer.

## Download

~~~bash
clusterflux artifact list --process <process-id>
clusterflux artifact download <artifact-id> --max-bytes 67108864
clusterflux artifact export <artifact-id> --receiver-node <node-id>
~~~

The download command returns scoped metadata authorization only. The link is
unguessable, expires, can be revoked, and is bound to the actor, tenant, project,
process, artifact, and policy context. The coordinator has no artifact-body
download stream and never returns artifact bytes as JSON or base64.

Use node export when the bytes are needed elsewhere. It uses the same direct
Iroh engine as task prefetch: the receiving node verifies the size and SHA-256,
atomically installs the file, and only then publishes the new location. Direct
artifact traffic has no Clusterflux byte quota. Public hosted relay-body bytes
must remain zero; self-hosted relay fallback is controlled by the operator.

## Performance invariants

Artifact bodies travel as raw bytes over pooled Iroh connections. Each active
stream uses a fixed, bounded buffer and asynchronous sequential file I/O; the
provider permits bounded concurrent streams, so one large transfer does not
globally serialize unrelated artifacts. File durability and metadata publication
happen at transfer boundaries, not once per body chunk.

Changes to this path must preserve the following invariants:

- no coordinator, web, JSON, or base64 artifact-body hop;
- no unbounded buffer or unbounded stream/task concurrency;
- no global lock held while artifact bytes are read, written, or sent;
- no per-chunk coordinator request, allocation, metadata rewrite, or durable flush;
- reuse an authorized peer connection rather than creating an endpoint per transfer;
- retain exact size and SHA-256 verification before atomic installation.

Hardware throughput measurements are diagnostic rather than a release gate or
goal. No high-speed-NIC benchmark is required for this lifecycle work. When
representative hardware happens to be available, comparison against direct Iroh
and disk baselines may inform later tuning; do not add parallel ranges, chunk
schedulers, per-chunk coordination, or fixed throttles without evidence. The
invariants above are the guard against introducing obvious software bottlenecks.

## Post-launch qualification

The current release does not claim measurements for two independent consumer/home,
office, or mobile-hotspot networks; global IPv6; Linux ARM64; Windows; public
multiarchitecture self-builds; or high-speed-NIC throughput. Those remain optional
post-launch, hardware-availability qualifications and are not release goals or
pass/fail gates.
