# Getting started

This guide uses the hosted coordinator. For your own coordinator, complete
[Self-hosting](self-hosting.md) first and then return to the node and run steps.

## 1. Install the commands

Install the latest stable Linux x86-64 release for your user:

~~~bash
curl -fsSL https://github.com/lesstuff/clusterflux/releases/latest/download/install.sh | sh
~~~

For a system-wide DEB or RPM installation:

~~~bash
curl -fsSL https://github.com/lesstuff/clusterflux/releases/latest/download/install.sh | sudo sh
~~~

Both paths include the commands and release-pinned compiler package under
`share/clusterflux`; the node verifies it and loads the compiler appliance into
rootless Podman on first startup.

Source contributors can build the commands with Cargo. A full source checkout
also contains release tooling that builds the compiler environment and reports
the immutable image ID accepted by `--system-compiler-image`.

On NixOS or another system with Nix, install the equivalent package with
`nix profile install --accept-flake-config github:lesstuff/clusterflux#clusterflux-tools`.
This accepts only the repository-declared public Clusterflux Cachix URL and
signing key, allowing Nix to download a matching stable build.

Install Cargo, rustc, and the `wasm32-unknown-unknown` Rust target for local
`clusterflux check`, `build`, `run`, and `debug`. Hosted automatic compilation
uses the attached node's packaged sandboxed compiler and requires no extra
compiler executable.

Install rootless Podman on each Linux node that will execute container-backed
environments.

## 2. Sign in and select your hosted project

~~~bash
clusterflux login --browser
clusterflux auth status
clusterflux project list
clusterflux project select <hosted-project-id>
~~~

The browser flow is owned by the configured Authentik identity provider. The CLI
stores an opaque Clusterflux session, not provider authorization codes or
provider tokens. Hosted login creates or links your single project; hosted
admission rejects additional project creation.

## 3. Enroll and start a node

Create a short-lived grant:

~~~bash
clusterflux node enroll --project-id <hosted-project-id> --json
~~~

Create the local node identity and exchange the grant once:

~~~bash
clusterflux node attach \
  --project-id <hosted-project-id> \
  --node workstation \
  --enrollment-grant "$ENROLLMENT_GRANT" \
  --json
~~~

Clusterflux creates and stores the node key and its coordinator, tenant, and
project scope locally with restricted permissions. The enrollment grant is not
needed again. Stop and restart the worker with the same stored identity:

~~~bash
clusterflux-node \
  --node workstation \
  --project-root "$PWD" \
  --worker \
  --emit-ready
~~~

Supplying `--public-key` and `CLUSTERFLUX_NODE_PRIVATE_KEY` is an advanced option
for nodes whose key material is managed externally. Check server-derived
liveness with:

~~~bash
clusterflux node list
clusterflux node status --node workstation
~~~

## 4. Inspect and run a bundle

A project keeps committed workflow source in `.clusterflux/Cargo.toml` and
`.clusterflux/main.rs` (plus optional Rust modules), with declared environments
under `envs/`. Locally this is a normal Cargo project: Cargo controls dependency
resolution and compilation, and `clusterflux check`, build, run, and debug add
Clusterflux descriptor/bundle handling around the Cargo result. The user owns
that local trust and resource boundary; no hosted sandbox is involved.

Forge-triggered automatic compilation is intentionally different. The
coordinator accepts only the built-in Clusterflux SDK at its exact supported
version and rejects unsupported Cargo features before assignment. It then waits
for an ordinary attached node matching the release system-bundle identity; the node compiles
the exact assignment source in rootless Podman. A project can therefore build
locally yet be rejected by the hosted subset with a specific error. The hosted
coordinator provides no compiler or native build compute.

The bundled examples use the SDK path in this checkout. This is a repository-demo
setup, not yet an external SDK distribution contract; unrelated repositories must
wait for the exact-revision Git dependency or published crate.

Local state is stored in
`.clusterflux-state/` and generated output in `target/clusterflux/`.

Task arguments and handles use portable canonical representations; they are not
host pointers or shared process memory.

~~~bash
clusterflux project inspect --project .
clusterflux check --project .
clusterflux run --project . main
~~~

From this checkout, the complete source-to-task-to-artifact path is:

~~~bash
clusterflux bundle inspect --project examples/hello-build
clusterflux run --project examples/hello-build build
clusterflux artifact list --process <process-id>
clusterflux artifact export <artifact-id> --receiver-node <node-id>
chmod +x target/clusterflux/node-artifacts/<node-id>/<artifact-id>
target/clusterflux/node-artifacts/<node-id>/<artifact-id>
~~~

The workflow snapshots `examples/hello-build`, starts its `compile` task in the
network-disabled Linux execution environment, and retains the real static executable returned by
that task.

Choose another entrypoint by replacing `build`. Clusterflux rejects an oversized
or invalid bundle before it creates the virtual process.

## 5. Inspect tasks and output

~~~bash
clusterflux process list
clusterflux process status
clusterflux task list
clusterflux logs
clusterflux artifact list
~~~

A failed task configured with `AwaitOperator` remains visible as awaiting action.
Restart it as a new attempt under the same logical task identity:

~~~bash
clusterflux task restart <task-id> --process <process-id> --yes
~~~

`examples/recovery-build` demonstrates this without a synthetic trap. It starts
two instances of `build_lane`; one completes while the other runs a command that
exits with status 23. Edit that command to produce the recovering output, then
restart the failed task. Its original join resolves from the replacement
attempt.

Commands that start asynchronous work print one exact bounded follow-up command.
The same waits are available directly for scripts and agents:

~~~bash
clusterflux wait process --process <process-id> --for terminal --timeout 30m
clusterflux wait run --run <run-id> --for terminal --timeout 30m
clusterflux wait run --repository <repository-id> --commit <commit-sha> \
  --for appeared --timeout 5m
clusterflux wait node --node workstation --for ready --timeout 5m
~~~

Every JSON command report includes a `guidance` object: either one validated
recommended argv array plus optional alternatives, or an explicit reason that
no follow-up is needed. Human output shell-quotes the same argv. Mutating and
confirmation-requiring alternatives are marked and are never run automatically.

Before long unattended work, require enough remaining login validity with
`clusterflux auth status --require-valid-for 45m`. For hosted repository
automation, `clusterflux runs diagnose <run-id>` returns the bounded relevant
failure and log tail, `clusterflux runs retry <run-id>` retries the same run,
and `clusterflux webhook deliveries` shows recent redacted admission results.
`clusterflux node doctor --node workstation` performs a read-only check of the
local identity, enrollment, liveness, container backend, and compiler status.

## 6. Debug in VS Code

Open the project in VS Code and start `Clusterflux: Launch Virtual Process`.
Set a breakpoint on a generated probe location and use Threads, Stack,
Variables, Continue, Pause, and Restart.

Breakpoints remain unverified until the coordinator installs them. Thread IDs
are stable for an exact logical task instance across snapshot updates and retry
attempts. Observer reconnect diagnostics do not manufacture stopped events, and
Continue succeeds only after the coordinator acknowledges resume.

A fully frozen Debug Epoch gives a consistent all-participant view. If a
participant cannot freeze within five seconds, the adapter reports a partial
epoch. You may inspect frozen participants, but values across running and frozen
tasks are not a consistent global snapshot. Continue resumes only participants
that acknowledged the freeze.

## 7. Receive an artifact directly

~~~bash
clusterflux artifact list --process <process-id>
clusterflux artifact export <artifact-id> --receiver-node <node-id>
~~~

Keep the receiving node running. It obtains a scoped, expiring lease and fetches
the bytes directly from a retaining node over Iroh. The receiver verifies the
artifact size and digest before atomically installing it under
`target/clusterflux/node-artifacts/<node-id>/<artifact-id>`. The coordinator carries no
artifact body bytes.
