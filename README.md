# Clusterflux

Clusterflux runs a Rust-defined workflow as one distributed virtual process. The
async main runs serverless, provisioning nodes to run tasks through rootless
containers. Tasks on nodes exchange data simply and efficiently.

The user experience is built to be as much as possible like building a regular
program. The processes are debuggable as normal through a debugger adapter.

The primary use case is to consolidate build processes into a single streamlined
developer experience. An example program can be seen below:

~~~rust
use clusterflux::prelude::*;

#[clusterflux::task(capabilities = "command")]
pub async fn compile(source: SourceSnapshot) -> Result<Artifact> {
    let executable = fs::output("hello-clusterflux")?;
    Command::new("cc")
        .args([
            "-Os",
            "-static",
            "-s",
            "fixture/hello-clusterflux.c",
            "-o",
            executable.as_str(),
        ])
        .cwd(source.mount()?)
        .env("SOURCE_DATE_EPOCH", "0")
        .network_disabled()
        .run()
        .await?;
    fs::publish(&executable).await
}

#[clusterflux::main]
pub async fn build() -> Result<Artifact> {
    let source = source::current_project().snapshot().await?;
    let compile = clusterflux::spawn!(compile(source))
        .on(clusterflux::env!("linux"))
        .await?;
    compile.join().await
}
~~~

After setup, this build pipeline could be deployed as easily as launching it
through your IDE. This repository includes a VS Code extension to make
development as straightforward as possible. A full collection of CLI tools is
included for advanced usage.

Clusterflux is explicitly local-first. It is trivial to provision existing
hardware as resources. Bulk data will typically not leave the local network,
allowing maximum throughput. The same capability, however, also makes it
possible to leverage cloud resources easily.

Start with [Getting started](docs/getting-started.md). It takes you through
authentication, project setup, node enrollment, a run, debugging, task restart,
and direct artifact interchange.

## Build a real executable

The primary example is intentionally small: [hello-build](examples/hello-build)
snapshots its source project, spawns one container-backed compile task, and
publishes the resulting executable as a retained artifact.

~~~bash
clusterflux bundle inspect --project examples/hello-build
clusterflux run --project examples/hello-build build
clusterflux artifact list --process <process-id>
clusterflux artifact export <artifact-id> --receiver-node <node-id>
chmod +x target/clusterflux/node-artifacts/<node-id>/<artifact-id>
target/clusterflux/node-artifacts/<node-id>/<artifact-id>
~~~

The final command prints `hello from a real Clusterflux build`. The source uses
only the public SDK path: current-project snapshot, `spawn!`, `Command::run`, and
artifact publication. See [recovery-build](examples/recovery-build) for two
same-definition task instances, a real command failure, and operator restart.

For the advanced example, see the repository's own
[`.clusterflux` workflow](.clusterflux/main.rs). The hosted commit path compiles
only the Rust files under `.clusterflux` with the release-pinned system bundle
on an ordinary compatible attached node. Its test, build, packaging, and GitHub release steps are
ordinary Clusterflux tasks; GitHub Actions and a separate release service are
not involved.

## What you get

- One virtual process with distinct task instances and restart attempts.
- Bundle-declared environments resolved by digest.
- Native work only on nodes you attach.
- Metadata-first artifacts whose bytes remain on retaining nodes by default.
- VS Code debugging backed by coordinator task and attempt snapshots.
- Full and partial Debug Epochs with explicit consistency status.
- Human Authentik sessions plus scoped public-key identities for agents and nodes.
- A public coordinator, node runtime, CLI, SDK, and DAP adapter for self-hosting.

## Install

Install the latest stable Linux x86-64 release without root:

~~~bash
curl -fsSL https://github.com/lesstuff/clusterflux/releases/latest/download/install.sh | sh
~~~

For a system-wide DEB or RPM installation, run the same verified installer as
root:

~~~bash
curl -fsSL https://github.com/lesstuff/clusterflux/releases/latest/download/install.sh | sudo sh
~~~

The release includes the public binaries and the release-pinned compiler
appliance consumed by `clusterflux-node`.

On NixOS or another system with Nix, install the equivalent package with
`nix profile install --accept-flake-config github:lesstuff/clusterflux#clusterflux-tools`.
The accepted flake configuration uses the public, signed Clusterflux Cachix
cache so a matching stable build is downloaded instead of compiled locally.

Source contributors can instead use `nix build .#clusterflux-tools` or build the
workspace with Cargo from a checkout of
[github.com/lesstuff/clusterflux](https://github.com/lesstuff/clusterflux).

Local workflow commands use your ordinary Cargo and Rust toolchain. Hosted
automatic workflows wait for one of the project's ordinary attached nodes to
verify the built-in bundle and immutable compiler environment; the hosted service
coordinates but provides no build compute. There is no separate compiler
service or user-facing workflow-compiler command to install.

The repository demo is ready with its exact-version local SDK path. SDK
distribution for unrelated external repositories is intentionally deferred;
those repositories cannot copy this local path until the SDK is published as an
exact-revision Git dependency or crate.

`.clusterflux` is a normal Cargo project locally, so local dependencies, caches,
diagnostics, and rust-analyzer behave normally. Forge-triggered hosted builds
accept a deliberately smaller manifest subset containing only the exact
Clusterflux SDK package/version, then compile the untrusted commit with the
release-pinned compiler appliance in rootless Podman on an attached user node.
Local and hosted output share one bundle/debug finalizer and schema, but their
compiler identities and module bytes need not match.

Rootless Podman is required on Linux nodes that build or run a declared
Containerfile environment. Install VS Code when you want the graphical debug
workflow.

## First run

For the hosted service:

~~~bash
clusterflux login --browser
clusterflux auth status
clusterflux project list
clusterflux node enroll --project-id <hosted-project-id> --json
clusterflux node attach --project-id <hosted-project-id> --node workstation \
  --enrollment-grant "$ENROLLMENT_GRANT"
~~~

The attach command creates and stores a local node key by default, then exchanges
the short-lived grant once. Start `clusterflux-node --worker` from the project
directory. See [Nodes](docs/nodes.md) for the complete sequence and the advanced
explicit-key option.

Choose an entrypoint and run it:

~~~bash
clusterflux bundle inspect --project examples/hello-build
clusterflux run --project examples/hello-build build
~~~

Inspect the result:

~~~bash
clusterflux process status
clusterflux task list
clusterflux logs
clusterflux artifact list
# Use the `artifact` value returned by the list command, for example:
clusterflux artifact export hello-clusterflux-4f61c2... --receiver-node <node-id>
~~~

The receiving node must be running. Artifact bytes move directly between Iroh
node endpoints; the coordinator only authorizes and tracks the interchange.

To run your own coordinator instead, follow [Self-hosting](docs/self-hosting.md).
The hosted website is not required for self-hosted projects.

## Documentation

- [Getting started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Nodes](docs/nodes.md)
- [Windows nodes](docs/windows-nodes.md)
- [Environments](docs/environments.md)
- [Artifacts](docs/artifacts.md)
- [Debugging](docs/debugging.md)
- [Task ABI](docs/task-abi.md)
- [Self-hosting](docs/self-hosting.md)
- [Security model](docs/security.md)
- [Security reporting](SECURITY.md)
