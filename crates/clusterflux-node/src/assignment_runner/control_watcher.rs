use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clusterflux_core::{AssignmentAuthority, TaskJoinResult, TaskSpec};
use clusterflux_node::WasmDebugControl;
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse, DebugAcknowledgementState};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::ChildJoinNotifications;
use crate::coordinator_session::AsyncCoordinatorSession;
use crate::daemon::Args;
use crate::node_identity::signed_node_assignment_request;

const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(1);
const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(250);
const CONTROL_RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(2);

pub(super) struct TaskControlWatchers {
    shutdown: CancellationToken,
    finished: Option<oneshot::Sender<()>>,
}

struct TaskControlContext {
    args: Args,
    process: String,
    task: String,
    task_definition: String,
    assignment_authority: AssignmentAuthority,
    node_private_key: String,
    cancellation_requested: CancellationToken,
    abort_requested: Arc<AtomicBool>,
    debug_control: Arc<WasmDebugControl>,
    task_args: Vec<(String, String)>,
    handles: Arc<Mutex<HashMap<u64, TaskSpec>>>,
    child_joins: Arc<ChildJoinNotifications>,
    command_status: Arc<Mutex<Option<String>>>,
}

struct ControlPoll {
    cancel_requested: bool,
    abort_requested: bool,
    debug_epoch: Option<u64>,
    debug_command: Option<String>,
    child_joins: Vec<TaskJoinResult>,
}

impl TaskControlWatchers {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn start(
        runtime: tokio::runtime::Handle,
        tasks: TaskTracker,
        args: Args,
        process: String,
        task: String,
        task_definition: String,
        assignment_authority: AssignmentAuthority,
        node_private_key: String,
        cancellation_requested: CancellationToken,
        abort_requested: Arc<AtomicBool>,
        debug_control: Arc<WasmDebugControl>,
        task_args: Vec<(String, String)>,
        handles: Arc<Mutex<HashMap<u64, TaskSpec>>>,
        child_joins: Arc<ChildJoinNotifications>,
        command_status: Arc<Mutex<Option<String>>>,
        node_shutdown: CancellationToken,
    ) -> Self {
        let shutdown = node_shutdown.child_token();
        let (finished, task_finished) = oneshot::channel();
        let context = Arc::new(TaskControlContext {
            args,
            process,
            task,
            task_definition,
            assignment_authority,
            node_private_key,
            cancellation_requested: cancellation_requested.clone(),
            abort_requested: Arc::clone(&abort_requested),
            debug_control: Arc::clone(&debug_control),
            task_args,
            handles,
            child_joins,
            command_status,
        });
        tasks.spawn_on(
            run_task_control_watcher(Arc::clone(&context), shutdown.child_token()),
            &runtime,
        );
        tasks.spawn_on(
            run_node_shutdown_watcher(
                abort_requested,
                cancellation_requested,
                debug_control,
                node_shutdown,
                task_finished,
            ),
            &runtime,
        );
        Self {
            shutdown,
            finished: Some(finished),
        }
    }

    pub(super) fn shutdown(&mut self) {
        self.shutdown.cancel();
        if let Some(finished) = self.finished.take() {
            let _ = finished.send(());
        }
    }
}

impl Drop for TaskControlWatchers {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn debug_handle_snapshot(handles: &Arc<Mutex<HashMap<u64, TaskSpec>>>) -> Vec<(String, String)> {
    let Ok(handles) = handles.lock() else {
        return vec![(
            "handle-registry-diagnostic".to_owned(),
            "runtime task handle registry was unavailable".to_owned(),
        )];
    };
    let mut snapshot = handles
        .iter()
        .map(|(handle_id, spec)| {
            (
                format!("task_handle_{handle_id}"),
                format!(
                    "definition={} instance={} state=active",
                    spec.task_definition, spec.task_instance
                ),
            )
        })
        .collect::<Vec<_>>();
    snapshot.sort_by(|left, right| left.0.cmp(&right.0));
    snapshot
}

async fn poll_control(
    context: &TaskControlContext,
    session: &AsyncCoordinatorSession,
) -> Result<ControlPoll, String> {
    let child_tasks = context
        .handles
        .lock()
        .map_err(|_| "Wasm task handle registry was unavailable".to_owned())?
        .values()
        .map(|spec| spec.task_instance.as_str().to_owned())
        .collect();
    let control_request = signed_node_assignment_request(
        &context.args,
        &context.node_private_key,
        &context.assignment_authority,
        "poll_task_control",
        CoordinatorRequest::PollTaskControl {
            tenant: context.args.tenant.clone(),
            project: context.args.project.clone(),
            process: context.process.clone(),
            node: context.args.node.clone(),
            task: context.task.clone(),
            child_tasks,
        },
    )
    .map_err(|error| error.to_string())?;
    let control = session.request(control_request).await?;
    let CoordinatorResponse::TaskControl {
        cancel_requested,
        abort_requested,
        child_joins,
        ..
    } = control
    else {
        return Err("coordinator returned an unexpected task-control response".to_owned());
    };
    if abort_requested {
        return Ok(ControlPoll {
            cancel_requested,
            abort_requested,
            debug_epoch: None,
            debug_command: None,
            child_joins,
        });
    }
    let debug_request = signed_node_assignment_request(
        &context.args,
        &context.node_private_key,
        &context.assignment_authority,
        "poll_debug_command",
        CoordinatorRequest::PollDebugCommand {
            tenant: context.args.tenant.clone(),
            project: context.args.project.clone(),
            process: context.process.clone(),
            node: context.args.node.clone(),
            task: context.task.clone(),
        },
    )
    .map_err(|error| error.to_string())?;
    let debug = session.request(debug_request).await?;
    let CoordinatorResponse::DebugCommand {
        epoch: debug_epoch,
        command: debug_command,
        ..
    } = debug
    else {
        return Err("coordinator returned an unexpected debug-command response".to_owned());
    };
    Ok(ControlPoll {
        cancel_requested,
        abort_requested: false,
        debug_epoch,
        debug_command,
        child_joins,
    })
}

async fn debug_acknowledgement(
    context: &TaskControlContext,
    epoch: u64,
    command: &str,
    shutdown: &CancellationToken,
) -> Option<(DebugAcknowledgementState, Option<String>)> {
    let freeze_timeout = Duration::from_millis(context.args.debug_freeze_timeout_ms);
    match command {
        "freeze" => {
            if std::env::var_os("CLUSTERFLUX_DEBUG_CONTROL_TRACE").is_some() {
                eprintln!(
                    "clusterflux debug control: node received freeze for epoch {epoch} task {} (debug={:?})",
                    context.task,
                    Arc::as_ptr(&context.debug_control)
                );
            }
            context.debug_control.request_freeze(epoch);
            let frozen = tokio::select! {
                frozen = context
                    .debug_control
                    .wait_until_frozen_async(epoch, freeze_timeout) => frozen,
                () = shutdown.cancelled() => return None,
            };
            if frozen {
                Some((DebugAcknowledgementState::Frozen, None))
            } else {
                context.debug_control.request_resume(epoch);
                Some((
                    DebugAcknowledgementState::Failed,
                    Some(format!(
                        "node execution did not reach a freezeable Wasm safepoint or verified native/Podman boundary within {} ms",
                        freeze_timeout.as_millis()
                    )),
                ))
            }
        }
        "resume" => {
            context.debug_control.request_resume(epoch);
            let running = tokio::select! {
                running = context
                    .debug_control
                    .wait_until_running_async(epoch, freeze_timeout) => running,
                () = shutdown.cancelled() => return None,
            };
            if running {
                Some((DebugAcknowledgementState::Running, None))
            } else {
                Some((
                    DebugAcknowledgementState::Failed,
                    Some(format!(
                        "node execution did not leave its verified frozen state within {} ms",
                        freeze_timeout.as_millis()
                    )),
                ))
            }
        }
        _ => Some((
            DebugAcknowledgementState::Failed,
            Some(format!("node received unknown debug command '{command}'")),
        )),
    }
}

async fn report_debug_state(
    context: &TaskControlContext,
    session: &AsyncCoordinatorSession,
    epoch: u64,
    state: DebugAcknowledgementState,
    message: Option<String>,
) -> Result<(), String> {
    let report = signed_node_assignment_request(
        &context.args,
        &context.node_private_key,
        &context.assignment_authority,
        "report_debug_state",
        CoordinatorRequest::ReportDebugState {
            tenant: context.args.tenant.clone(),
            project: context.args.project.clone(),
            process: context.process.clone(),
            node: context.args.node.clone(),
            task: context.task.clone(),
            epoch,
            state: state.clone(),
            current_source_location: if state == DebugAcknowledgementState::Frozen {
                context.debug_control.current_source_location()
            } else {
                None
            },
            stack_frames: if state == DebugAcknowledgementState::Frozen {
                let mut frames = context.debug_control.stack_frames();
                if let Some(frame) = frames.first_mut() {
                    *frame = format!("{}::wasm / {frame}", context.task_definition);
                } else {
                    frames.push(format!("{}::wasm", context.task_definition));
                }
                frames
            } else {
                Vec::new()
            },
            local_values: Vec::new(),
            task_args: context.task_args.clone(),
            handles: debug_handle_snapshot(&context.handles),
            command_status: context
                .command_status
                .lock()
                .ok()
                .and_then(|status| status.clone()),
            recent_output: Vec::new(),
            message,
        },
    )
    .map_err(|error| error.to_string())?;
    session.request(report).await.map(|_| ())
}

async fn run_task_control_watcher(context: Arc<TaskControlContext>, shutdown: CancellationToken) {
    let mut reconnect_backoff = Duration::from_millis(100);
    loop {
        let session = match AsyncCoordinatorSession::connect_with_timeouts(
            &context.args.coordinator,
            CONTROL_CONNECT_TIMEOUT,
            CONTROL_IO_TIMEOUT,
        ) {
            Ok(session) => session,
            Err(_) => {
                tokio::select! {
                    () = tokio::time::sleep(reconnect_backoff) => {}
                    () = shutdown.cancelled() => return,
                }
                reconnect_backoff = (reconnect_backoff * 2).min(CONTROL_RECONNECT_BACKOFF_MAX);
                continue;
            }
        };
        loop {
            let polled = tokio::select! {
                result = poll_control(&context, &session) => result,
                () = shutdown.cancelled() => return,
            };
            let Ok(poll) = polled else {
                break;
            };
            reconnect_backoff = Duration::from_millis(100);
            context.child_joins.record(poll.child_joins);
            if poll.cancel_requested {
                context.cancellation_requested.cancel();
            }
            if poll.abort_requested {
                context.abort_requested.store(true, Ordering::Release);
                context.cancellation_requested.cancel();
                return;
            };
            if let (Some(epoch), Some(command)) = (poll.debug_epoch, poll.debug_command) {
                let Some((state, message)) =
                    debug_acknowledgement(&context, epoch, &command, &shutdown).await
                else {
                    return;
                };
                let reported = tokio::select! {
                    result = report_debug_state(&context, &session, epoch, state, message) => result,
                    () = shutdown.cancelled() => return,
                };
                if reported.is_err() {
                    break;
                }
            }
            tokio::select! {
                () = tokio::time::sleep(CONTROL_POLL_INTERVAL) => {}
                () = shutdown.cancelled() => return,
            }
        }
        tokio::select! {
            () = tokio::time::sleep(reconnect_backoff) => {}
            () = shutdown.cancelled() => return,
        }
        reconnect_backoff = (reconnect_backoff * 2).min(CONTROL_RECONNECT_BACKOFF_MAX);
    }
}

async fn run_node_shutdown_watcher(
    abort_requested: Arc<AtomicBool>,
    cancellation_requested: CancellationToken,
    debug_control: Arc<WasmDebugControl>,
    node_shutdown: CancellationToken,
    task_finished: oneshot::Receiver<()>,
) {
    tokio::select! {
        biased;
        () = node_shutdown.cancelled() => {
            abort_requested.store(true, Ordering::Release);
            cancellation_requested.cancel();
            if let Some(epoch) = debug_control.requested_epoch() {
                debug_control.request_resume(epoch);
            }
        }
        _ = task_finished => {}
    }
}

#[cfg(test)]
mod tests {
    use super::TaskControlWatchers;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;
    use tokio_util::task::TaskTracker;

    #[test]
    fn owned_watchers_cancel_and_join_every_task() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let handle = runtime.handle().clone();
        let shutdown = CancellationToken::new();
        let tracker = TaskTracker::new();
        let first_finished = Arc::new(AtomicBool::new(false));
        let second_finished = Arc::new(AtomicBool::new(false));
        for finished in [Arc::clone(&first_finished), Arc::clone(&second_finished)] {
            let cancelled = shutdown.child_token();
            tracker.spawn_on(
                async move {
                    cancelled.cancelled().await;
                    finished.store(true, Ordering::Release);
                },
                &handle,
            );
        }
        let mut watchers = TaskControlWatchers {
            shutdown,
            finished: None,
        };

        watchers.shutdown();
        tracker.close();
        runtime.block_on(tracker.wait());

        assert!(first_finished.load(Ordering::Acquire));
        assert!(second_finished.load(Ordering::Acquire));
    }
}
