# Task ABI

Clusterflux tasks cross a canonical, versioned Wasm boundary.

## Values

Small arguments and results use canonical JSON-compatible values. Large or
capability-bearing values use typed handles. A structured boundary value carries
both its JSON structure and the complete typed handle table required to
materialize it.

Portable handles carry the minimum stable value needed to cross the task ABI,
such as an artifact ID, digest, and size. Tenant, project, process, producer,
path, retaining location, and authorization state are coordinator-side
metadata; they are not portable authority fields supplied by task code. The SDK
encodes handles as explicit placeholders and the runtime replaces only
placeholders that match the declared type and authoritative coordinator
metadata.

A malformed, missing, extra, cross-scope, or type-mismatched handle fails closed.
The runtime does not reconstruct authority from a string path or caller-supplied
display field.

## Tasks

Use the macros and SDK types:

~~~rust
#[clusterflux::task]
async fn compile(input: clusterflux::Artifact) -> Result<clusterflux::Artifact, String> {
    // Task body
}

#[clusterflux::main]
async fn build() -> Result<(), String> {
    // Spawn and join tasks
}
~~~

Each spawn produces a TaskSpec containing the logical task instance,
definition, environment identity and digest, canonical arguments, handles, VFS
epoch, bundle identity, dispatch ABI, and failure policy.

Use distinct logical task instances when you spawn the same definition twice.
A restart preserves that logical identity and creates a distinct attempt.

## Failure policy

"FailFast" is the default. "AwaitOperator" leaves the logical join pending after
failure so you can inspect, accept, cancel, or restart the attempt. Side effects
outside the VFS boundary are at-least-once across retries; make them idempotent
or add your own deduplication key.
