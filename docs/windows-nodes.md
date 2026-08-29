# Windows nodes

A Windows node executes Windows tasks in process-isolated containers. The
coordinator still does no compilation or execution: a compiler-capable Linux
node compiles the workflow, then the coordinator places Windows environments on
the Windows node.

## Host setup

Use a Windows host and Windows base image with compatible kernels. Install and
start containerd, BuildKit, `nerdctl`, and a CNI network. Confirm a
process-isolated container works before starting Clusterflux:

~~~powershell
nerdctl run --rm --isolation process mcr.microsoft.com/windows/nanoserver:ltsc2025 cmd /c ver
~~~

Hyper-V is not required for process isolation. This backend applies CPU and
memory ceilings, uses a read-only source bind mount, and exposes only the task
output directory as a writable host mount. The container's other writable layer
is discarded. Windows `runhcs` does not expose Clusterflux's per-task PID limit,
so the node reports that limit honestly rather than pretending to enforce it.

Define a Windows environment explicitly:

~~~toml
version = 1
name = "windows-build"
os = "windows"
arch = "x86_64"
capabilities = ["command", "containers", "containerd_nerdctl"]
secrets = []
~~~

Install the public Windows node package from an Administrator PowerShell:

~~~powershell
irm https://github.com/lesstuff/clusterflux/releases/latest/download/install-windows.ps1 | iex
~~~

The installer verifies the release ZIP before extraction and installs into
`%LOCALAPPDATA%\Clusterflux` by default. An elevated install adds a
program-scoped inbound UDP rule for authenticated direct artifact transfers. A
non-elevated install prints that missing action instead. The installer does not
install containerd, BuildKit, nerdctl, CNI, or a Windows service.

Build the immutable task image during node setup, not during a task:

~~~powershell
clusterflux-environment-setup.exe --project-root C:\src\project --name windows-build
~~~

The environment definition must be committed. Restart the worker after setup so
the coordinator sees the new cached image.

Before enrollment, verify the complete runtime and selected environment:

~~~powershell
clusterflux node doctor --full --environment windows-build
~~~

The normal public release workflow builds both `clusterflux-node.exe` and
`clusterflux-environment-setup.exe` on a persistent Windows worker. Automatic
workflow compilation remains on a compatible Linux node.

If `nerdctl` uses a non-default CNI directory, set `NETCONFPATH` in the service
environment before both setup and worker startup.

## Enroll and run

Create a one-use enrollment grant from an authenticated CLI on any machine:

~~~bash
clusterflux node enroll --project-id <project-id> --json
~~~

Use the grant once on Windows so the node stores its scoped key, then omit it
from the persistent service command:

~~~powershell
clusterflux-node.exe `
  --coordinator https://coordinator.example `
  --tenant <tenant> `
  --project-id <project-id> `
  --node windows-builder `
  --project-root C:\src\project `
  --enrollment-grant <one-use-grant> `
  --worker --emit-ready

clusterflux-node.exe `
  --node windows-builder `
  --project-root C:\src\project `
  --task-cpus 8 `
  --task-memory-gib 16 `
  --worker --emit-ready
~~~

Stop the first invocation after it reports ready. The stored identity supplies
the coordinator, tenant, and project scope to subsequent starts. Configure the
second command as a normal startup service and keep the project checkout at the
same path.

The node defaults to containers and execution-only policy. It never falls back
to native commands when containerd is unavailable. Native execution exists only
for operator-controlled development and requires the explicit
`--dangerous-allow-native-commands` startup flag.
