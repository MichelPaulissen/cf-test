use anyhow::Result;
use clusterflux_protocol::CoordinatorRequest;
use serde_json::{json, Value};

use crate::client::{
    authenticated_or_local_trusted_request, list_task_events_if_available_with_session,
    JsonLineSession,
};
use crate::config::StoredCliSession;
use crate::process_events::{task_restart_request_summary, task_summaries};
use crate::{confirmation_required_report, TaskListArgs, TaskRestartArgs};

#[cfg(test)]
pub(crate) fn task_list_report(args: TaskListArgs) -> Result<Value> {
    task_list_report_with_session(args, None)
}

pub(crate) fn task_list_report_with_session(
    args: TaskListArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    let events = list_task_events_if_available_with_session(
        args.scope.coordinator.as_deref(),
        &args.scope,
        args.process.clone(),
        stored_session,
    )?;
    let tasks = task_summaries(events.as_ref());
    Ok(json!({
        "command": "task list",
        "process": args.process,
        "tasks": tasks,
        "events": events,
    }))
}

#[cfg(test)]
pub(crate) fn task_restart_report(args: TaskRestartArgs) -> Result<Value> {
    task_restart_report_with_session(args, None)
}

pub(crate) fn task_restart_report_with_session(
    args: TaskRestartArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    if !args.yes {
        return Ok(confirmation_required_report(
            "task restart",
            "restart_selected_task",
            json!({
                "coordinator": args.scope.coordinator,
                "tenant": args.scope.tenant,
                "project": args.scope.project,
                "process": args.process,
                "task": args.task,
            }),
            format!(
                "clusterflux task restart {} --process {} --yes",
                args.task, args.process
            ),
        ));
    }
    if let Some(coordinator) = &args.scope.coordinator {
        let mut session = JsonLineSession::connect(coordinator)?;
        let response = session.request_allow_error(authenticated_or_local_trusted_request(
            coordinator,
            stored_session,
            CoordinatorRequest::RestartTask {
                tenant: args.scope.tenant.clone(),
                project: args.scope.project.clone(),
                actor_user: args.scope.user.clone(),
                process: args.process.clone(),
                task: args.task.clone(),
                replacement_bundle: None,
            },
        )?)?;
        let restart_request = task_restart_request_summary(&response, !args.yes);
        return Ok(json!({
            "command": "task restart",
            "coordinator": coordinator,
            "process": args.process,
            "task": args.task,
            "requires_confirmation": !args.yes,
            "restart_request": restart_request,
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "task restart",
        "status": "requires_coordinator",
        "requires_confirmation": !args.yes,
        "process": args.process,
        "task": args.task,
        "restart_request": {
            "status": "requires_coordinator",
            "operation": "restart_selected_task",
            "explicit_user_action": true,
            "clean_boundary_required": true,
        },
    }))
}
