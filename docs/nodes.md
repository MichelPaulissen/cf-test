# Nodes

On a compatible Linux host, the normal node advertises the release-pinned
workflow compiler system bundle after its immutable environment and sandbox
pass self-check. The same node can compile and execute a workflow. Use
`--no-workflow-compilation` for execution-only policy or `--system-tasks-only`
to accept release-owned pre-process tasks without accepting project tasks.
System-task-only policy also refuses secret, artifact, source, and debugger
operations.

The platform release archive installs the compiler OCI archive beside the node
binary. The node loads it on first startup and verifies its release identity;
there is no second compiler executable or service to install. A source-tree
developer build can use the full checkout's release tooling and pass the
reported image ID with `--system-compiler-image`.

Rootless Podman is the environment and compiler backend. A self-check failure
marks automatic compilation unavailable while the node's other capabilities
remain usable. Node status reports the exact availability or mismatch reason.
The machine owner controls the node and can inspect its local source and output;
the sandbox protects the node host from workflow code, not workflow data from
the node owner. Attach only machines whose operator you trust with that project.

Your node runs real commands and retains real output bytes. Enroll it once, then
restart it with the same public-key identity.

## Enroll

~~~bash
clusterflux node enroll --project-id <project-id> --json
clusterflux node attach \
  --project-id <project-id> \
  --node workstation \
  --enrollment-grant "$ENROLLMENT_GRANT"
~~~

Treat the enrollment grant as a short-lived secret. It is exchanged once and is
not a worker credential. By default, `clusterflux node attach` creates and stores
a local node key with restricted permissions, along with its coordinator,
tenant, and project scope. Use an explicit `--public-key` with
`CLUSTERFLUX_NODE_PRIVATE_KEY` only when external secret management owns the key
pair.

## Run the worker

~~~bash
clusterflux-node \
  --node workstation \
  --project-root "$PWD" \
  --worker \
  --emit-ready
~~~

Start the worker from the project directory when tasks need a local checkout.
The worker reports detected command, container, source, VFS, environment, OS,
and architecture capabilities. Use `clusterflux node attach --cap <capability>`
only when detection needs an explicit override.

Windows nodes use process-isolated Windows containers through containerd and
`nerdctl`. They are execution-only: keep a compiler-capable Linux node online
to compile the platform-neutral workflow. See [Windows nodes](windows-nodes.md)
for setup and the platform-specific isolation limits.

Native workflow commands are disabled on every supported platform. The node
only enables them when its operator starts it with the conspicuous
`--dangerous-allow-native-commands` override.

Project task containers default to 2 CPUs, 2 GiB of memory, and 256 processes
or threads. Operators can raise those ceilings with `--task-cpus`,
`--task-memory-gib`, and `--task-pids-limit`; large Rust release builds commonly
need more than the defaults. Keep the values within the host's real capacity.

## Liveness

~~~bash
clusterflux node list
clusterflux node status --node workstation
clusterflux node doctor --node workstation
~~~

The coordinator marks a node stale after its accepted heartbeat age exceeds the
configured threshold. Stale nodes are excluded before placement and before a
retained-node download link is created.

`node doctor` is read-only. It checks the stored project-scoped identity,
coordinator enrollment and reachability, reported container capabilities, and
automatic compiler availability. To wait for a worker without polling status:

~~~bash
clusterflux wait node --node workstation --for ready --timeout 5m
~~~

## Drain and provider release

Ephemeral/provider-backed workers begin draining when they receive no assignment
before the startup deadline (60 seconds by default), or after the post-work idle
deadline (30 seconds by default). Activity resets the idle timer, so a worker can
accept a short burst of tasks without being torn down between them. Persistent nodes
do not use these automatic timers. A draining node receives no new tasks. The
coordinator moves held sole-copy artifacts to an eligible live node, lets active
tasks/transfers finish, and releases the provider as soon as no real blocker remains.

`clusterflux node status <node>` and the website show the same lifecycle state,
soft/hard deadlines, running and queued task counts, active transfer count, retained
bytes, release reason, and user-facing blockers such as a running task, artifact
movement, restart retention, download, or paused debug session. Network protocol
details are reserved for diagnostics.

At the soft deadline Clusterflux drops optional explicit-retention holds and
prioritizes required relocation. Before the hard deadline, required state remains a
real blocker and is never silently discarded. At the hard deadline, finalization is
terminal and deterministic: active virtual processes are aborted, active transfers
are cancelled, remaining local retention is invalidated, and the recorded release
reason explains the policy action. The legacy `--provider-deadline-epoch-seconds`
flag is an alias for the hard deadline.

## Local source

A bind-mounted local checkout is fast and avoids transferring the repository,
but it is non-hermetic: uncommitted changes, ignored files, and concurrent
editor writes can affect the command. Use a content-addressed source snapshot
when reproducibility matters.

## Revoke

~~~bash
clusterflux node revoke --node workstation --yes
clusterflux wait node --node workstation --for gone --timeout 5m
~~~

Revocation removes the node identity and its live descriptor. Subsequent signed
requests fail. Artifacts retained only by that node become unavailable unless
you explicitly synchronized them elsewhere.
