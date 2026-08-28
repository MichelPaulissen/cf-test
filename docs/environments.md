# Environments

Clusterflux disables network access while a task executes. Materializing an
environment for the first time can still fetch declared inputs; subsequent task
execution uses the materialized environment with networking disabled.

Declare environments in the bundle under:

~~~text
envs/<name>/Containerfile
envs/<name>/Dockerfile
~~~

Reference one by logical name:

~~~rust
use clusterflux::env;

let linux = env!("linux");
~~~

Bundle inspection reports every discovered environment and its digest:

~~~bash
clusterflux bundle inspect --project .
~~~

The bundle definition is authoritative for every spawn. The coordinator passes
the declared environment identity and digest in the TaskSpec, and the node
resolves that exact definition. A same-named local recipe with different bytes
is rejected rather than substituted.

On Linux, container-backed environments use rootless Podman. Clusterflux does
not enable privileged containers by default.

On Windows, container-backed environments use containerd through `nerdctl` and
require process isolation. The operator prebuilds the exact declared image with
`clusterflux-environment-setup`; tasks never replace a missing image with a
native command. See [Windows nodes](windows-nodes.md).

Environment setup reads definitions from the clean, committed current Git
revision so line-ending conversion cannot change their identity. Commit changes
under `envs/` before setup, then restart the node so it advertises the refreshed
cache inventory.

A task may use a bind-mounted local checkout for speed. That source path is
non-hermetic. Choose a source snapshot when you need a reproducible input
identity independent of the current working tree.
