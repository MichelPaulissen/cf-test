# clusterflux-client

`clusterflux-client` is the public, typed Rust boundary for a Clusterflux web
backend. It talks to the same versioned control and login endpoints as the CLI.
Callers do not construct JSON envelopes or place session secrets into request
objects.

The crate intentionally contains no coordinator implementation, persistence
types, scheduler policy, or website-specific business rules. A web backend only
needs this crate to authenticate and work with account status, projects, Agent
keys, node enrollment and liveness, current/recent processes, task attempts,
recent logs, artifacts, quota state, process control, task recovery, and Debug
Epoch state. It does not expose workflow launch or whole-process replay.

```rust,no_run
use clusterflux_client::{ClusterfluxClient, SessionCredential};

# async fn example() -> Result<(), clusterflux_client::ClientError> {
let credential = SessionCredential::from_secret(
    std::env::var("CLUSTERFLUX_SESSION_SECRET").expect("server-side session secret"),
);
let client = ClusterfluxClient::connect("https://clusterflux.lesstuff.com")?
    .with_session_credential(&credential);

let account = client.account_status().await?;
let nodes = client.list_nodes().await?;
let processes = client.list_processes(None, 20).await?;
# let _ = (account, nodes, processes);
# Ok(())
# }
```

## Login boundary

`begin_browser_login` starts the hosted Authentik flow. The identity callback
returns only to the fixed configured website URL with a short-lived handoff.
The website backend calls `exchange_browser_login_handoff` once and stores the
returned `SessionCredential` only in encrypted server-side session storage.
The credential has redacted `Debug` output and deliberately does not implement
Serde serialization. Logout calls the existing session-revocation operation.

The browser must not receive or persist the Clusterflux session credential,
provider tokens, authorization code, PKCE verifier, or CLI polling secret.

## Errors, bounds, and transport

API failures are returned as `ClientError::Api(ApiError)`. Decisions should use
the stable `code`, `category`, `retryable`, and `request_id` fields, while
`message` is for people. The client rejects an error whose request ID does not
match the originating request.

Paginated list methods require an explicit bounded page size. Process pages are
limited to 100 entries; node, artifact, and recent-log pages to 200.
`list_nodes()` is a bounded first-page convenience; `list_nodes_page()` exposes
its cursor. Recent logs are ephemeral and can report truncation or sequence
loss. Artifact download links are bounded control-plane metadata only; artifact
bytes move directly between authorized nodes through the artifact interchange
engine and never through this HTTP/control client.

`ControlTransport` has bounded connect and I/O timeouts and performs blocking
network work outside the async executor. Dropping a request future cancels the
caller’s wait; any already-started blocking I/O remains bounded by its timeout.
`MockTransport` supplies deterministic responses and records exact envelopes
for application tests.

`CLIENT_API_VERSION` is the one supported control protocol version. The
checked-in `web_operations.json` contract fixture records every website
operation and its stable error shape, and the crate’s contract suite checks the
fixture.
