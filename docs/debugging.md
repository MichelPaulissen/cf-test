# Debugging

The DAP runtime observer keeps one coordinator session open and reconnects it
with a 100 ms to 5 second exponential backoff. Polling is responsive around
debug actions (100 ms) and backs off to one observation cycle every 5 seconds
while idle. A cycle makes at most four coordinator requests, so steady-state
idle traffic is bounded at 0.8 requests per second per debug session.

The VS Code extension uses the Debug Adapter Protocol and the coordinator's
authoritative process, task, attempt, and Debug Epoch APIs.

## Launch

Open your project and start "Clusterflux: Launch Virtual Process". The adapter
acknowledges launch configuration immediately, then builds and starts the
selected entrypoint in the background. You can keep using the debug UI while a
long-running process is attached. The adapter replaces its thread view with
coordinator task snapshots as they arrive; product mode does not infer threads
from completion events or demo fixtures.

Each task view includes its logical task, attempt ID, definition, state, node,
environment, arguments, typed handles, command status, VFS checkpoint, probe
source when known, and restart compatibility. Unknown source remains unknown.

## Breakpoints and Debug Epochs

When a breakpoint is hit, the coordinator asks every active participant to
freeze. A fully frozen epoch is a consistent all-participant view.

You do not need to configure a breakpoint before launch. Breakpoint changes are
sent to the running coordinator, and a stopped event is emitted only after an
executing Wasm probe reports a real hit. Pause, continue, inspection, and
disconnect requests remain responsive while the adapter observes the runtime in
the background. Attach does not fabricate an initial breakpoint.

If one or more participants cannot freeze within five seconds, the epoch becomes
partially frozen when at least one participant did freeze. The adapter warns
that running and frozen tasks do not form a consistent global snapshot. You may
inspect the acknowledged participants and resume them cleanly. Missing or failed
participants remain explicit.

Stack frames, Wasm locals, task arguments, handles, command status, and output
come from runtime acknowledgements. No frame or value is fabricated when the
runtime did not report it.

## Continue and restart

Continue responds immediately, then resumes only participants that acknowledged
the freeze while runtime observation continues in the background.

Restarting a terminal task rebuilds the bundle and checks its clean entry
checkpoint. A compatible restart creates a new attempt under the same logical
task identity. Earlier attempt history remains inspectable, and the logical join
continues. An active task or an incompatible boundary requires a whole-process
restart.

Source stepping is not simulated. Unsupported stepping fails explicitly.
