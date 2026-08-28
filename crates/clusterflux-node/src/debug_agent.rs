use std::time::{Duration, Instant};

use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};

use crate::coordinator_session::CoordinatorSession;
use crate::daemon::{Args, RuntimeTask};
use crate::node_identity::signed_node_assignment_request;

pub(crate) async fn poll_task_cancellation(
    session: &mut CoordinatorSession,
    args: &Args,
    task: &RuntimeTask,
    node_private_key: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_millis(args.control_poll_ms);
    loop {
        let control = session.request_signed(|| {
            signed_node_assignment_request(
                args,
                node_private_key,
                &task.assignment_authority,
                "poll_task_control",
                CoordinatorRequest::PollTaskControl {
                    tenant: args.tenant.clone(),
                    project: args.project.clone(),
                    process: task.process.clone(),
                    node: args.node.clone(),
                    task: task.task.clone(),
                    child_tasks: Vec::new(),
                },
            )
        })?;
        let CoordinatorResponse::TaskControl {
            cancel_requested,
            abort_requested,
            ..
        } = control
        else {
            return Err("coordinator returned an unexpected task-control response".into());
        };
        if cancel_requested || abort_requested {
            return Ok(true);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        tokio::time::sleep((deadline - now).min(Duration::from_millis(100))).await;
    }
}
