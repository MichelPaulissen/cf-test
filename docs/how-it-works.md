# How Clusterflux works

Clusterflux is a distributed build runtime.

Most CI systems ask you to describe a graph of jobs and send those jobs to
runners. Clusterflux uses a different model:

> **The workflow is a Rust program, and the whole distributed run behaves like
> one program.**

A project can contain:

```text
.clusterflux/
  Cargo.toml
  main.rs
  tasks.rs

envs/
  linux/
    Containerfile
```

The Rust code is the orchestration. Environments describe where native work can
run. Machines you attach provide the compute.

That is the core idea. The rest of Clusterflux exists to make that model work
without hiding where computation and data actually live.

## If you already know CI

The rough translation is:

| Conventional CI | Clusterflux |
| --- | --- |
| Workflow file | Rust program under `.clusterflux/` |
| Workflow run | Virtual process |
| Job | Task / virtual thread |
| Runner | Node |
| `needs` / dependency graph | `await` / `join()` |
| Runner image | `env!("linux")` |
| Uploaded artifact | `Artifact` handle |
| Re-run failed job | Restart task as a new attempt |
| Debug from logs | Debug the whole process in VS Code |

The important difference is not just replacing YAML with Rust.

The build keeps the semantics of a program: functions, types, control flow,
errors, async operations, loops, conditionals, and debugger-visible execution.

## One build is one virtual process

A workflow starts at a normal async entrypoint:

```rust
#[clusterflux::main]
async fn build() -> Result<Artifact> {
    let source = source::current_project().snapshot().await?;

    let compile = clusterflux::spawn!(compile(source))
        .on(clusterflux::env!("linux"))
        .await?;

    compile.join().await
}
```

`build()` is orchestration logic.

When it spawns `compile`, Clusterflux creates a logical task and places it on an
attached node that can run the requested environment.

Conceptually:

```text
Virtual process: build
│
├── main                         coordinator
├── compile                     node A
├── test                        node B
└── package                     node A
```

Those tasks may run on different physical machines, but Clusterflux presents
them as threads of one logical process.

That is also why the debugger can show the distributed build as one debug
target instead of a collection of unrelated remote jobs.

## The coordinator coordinates; nodes do the work

The coordinator handles:

```text
identity
projects
task placement
joins and retries
debug coordination
artifact metadata
node discovery
authorization
```

It does **not** run your compiler, shell commands, containers, or normal build
processes.

Real work happens on nodes you attach:

```text
your workstation
a server
a VM
a machine on another network
an ephemeral cloud machine
```

For a small setup, one node can do everything:

```text
compile automatic .clusterflux workflows
run build commands
hold source and caches
retain artifacts
participate in debugging
```

Adding more nodes gives the same program more places to run compatible work. It
does not introduce another workflow model.

### Why?

Because managed coordination is useful without requiring the coordinator
operator to own your build machines.

That keeps hosted Clusterflux small, makes self-hosting natural, and lets work
stay on the machine that already has the source, caches, and outputs.

## Environments describe requirements, not machines

Workflow code usually selects an environment:

```rust
clusterflux::spawn!(compile(source))
    .on(clusterflux::env!("linux"))
    .await?;
```

`env!("linux")` refers to a project resource such as:

```text
envs/linux/Containerfile
```

Clusterflux finds a node capable of materializing and running that environment.

The workflow says:

> Run this task in the Linux environment.

It does not say:

> Run job 7 on runner `build-machine-3`.

That keeps the program portable while still allowing placement to prefer the
node that already has the right source, environment, cache, or artifacts.

## Data stays where it already is

Distributed build systems can easily become distributed file-copy systems.

Clusterflux follows a simpler rule:

```text
move metadata eagerly
move bytes lazily
run work where the bytes already are
```

Small task arguments are copied normally.

Large or location-sensitive objects use handles:

```text
SourceSnapshot
Artifact
Blob
```

Passing an `Artifact` to another task does not automatically upload it through
the coordinator.

If the consumer runs on the same node, the bytes stay local. If another node
actually needs them, the nodes transfer the bytes directly.

```text
node A -------- artifact bytes --------> node B
   \                                      /
    \---- metadata / authorization -----/
                  coordinator
```

This is why Clusterflux uses explicit handles instead of making ordinary values
secretly trigger large network transfers.

## Automatic workflows compile on your nodes too

For a manual local run, `.clusterflux` is an ordinary Cargo project and your
local Cargo toolchain compiles it.

For an automatic forge-triggered run, Clusterflux schedules its built-in,
release-pinned workflow compiler onto an attached compatible node.

So an automatic run looks roughly like:

```text
commit/webhook
    │
    ▼
coordinator validates workflow input
    │
    ▼
attached node compiles .clusterflux
    │
    ▼
coordinator validates the result
    │
    ▼
virtual process starts
    │
    ├── task -> node A
    └── task -> node B
```

If no compatible node is connected, the run waits for one. The hosted
coordinator does not silently turn into a build worker.

## Debugging is part of the model

A workflow is code, so Clusterflux treats debugging as a normal way to
understand it.

VS Code can see:

```text
Process: build

Threads:
  main
  compile linux
  test
  package
```

A breakpoint in one task can create a **Debug Epoch** that stops the
participants in the virtual process and exposes their state through one debugger
session.

You can inspect task arguments, stacks, simple locals, handles, command state,
and recent output.

A failed task can also be restarted as a new attempt from a defined task
boundary.

The abstraction is the logical program, not the physical machines. Node IDs,
network paths, leases, and artifact locations are available when you need them,
but they do not have to define the normal development loop.

## Why not just use YAML with better runners?

CI workflows tend to become programs anyway:

```text
conditions
matrices
dependencies
retries
branch-specific behavior
generated values
scripts
artifact passing
manual controls
```

At that point the workflow language is effectively a constrained programming
language with a separate execution and debugging model.

Clusterflux starts with the premise that the orchestration **is a program**.

Rust provides the control flow and type system. Clusterflux adds only the
distributed operations ordinary Rust does not provide:

```text
spawn a task elsewhere
select an execution environment
pass distributed handles
join task results
coordinate failure and restart
debug the distributed process
```

## What Clusterflux is not

Clusterflux is not:

- a fleet of free hosted runners;
- a Kubernetes wrapper;
- a remote shell multiplexer;
- a build cache pretending to be a CI system;
- an interpreter for GitHub Actions YAML;
- a system that pretends arbitrary process state can transparently move between machines.

The hosted service provides a convenient control plane. The runtime, CLI, node,
SDK, and coordinator remain open source and can be self-hosted.

## The idea in one sentence

> **Write the build as a normal Rust program, let attached machines execute the
> parts that need real compute, and keep the whole distributed run understandable
> as one debuggable process.**

That is why Clusterflux has virtual processes, tasks, nodes, environments,
typed handles, direct artifact transfer, and a small coordinator instead of a
traditional workflow graph plus a hosted runner fleet.

## Continue

- [Getting started](getting-started.md) — install Clusterflux, attach a node, and run something.
- [Architecture](architecture.md) — the detailed control-plane and runtime design.
- [Debugging](debugging.md) — virtual threads, breakpoints, Debug Epochs, and restart.
- [Artifacts](artifacts.md) — locality, retention, and direct transfer.
- [Nodes](nodes.md) — node enrollment, execution, and lifecycle.
