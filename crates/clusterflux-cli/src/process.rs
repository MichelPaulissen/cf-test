use anyhow::Result;
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};
use serde_json::{json, Value};

use crate::client::{
    authenticated_or_local_trusted_request, list_task_events_if_available_with_session,
    stored_session_for_coordinator, JsonLineSession,
};
use crate::config::StoredCliSession;
use crate::process_events::{
    process_cancel_request_summary, process_restart_request_summary, process_state_from_tasks,
    task_summaries,
};
use crate::{
    confirmation_required_report, CliScopeArgs, ProcessAbortArgs, ProcessCancelArgs,
    ProcessListArgs, ProcessRestartArgs, ProcessStatusArgs,
};

pub(crate) fn hydrate_process_scope(
    scope: &mut CliScopeArgs,
    stored_session: Option<&StoredCliSession>,
) {
    if scope.coordinator.is_none() {
        scope.coordinator = stored_session
            .filter(|session| session.session_secret.is_some())
            .map(|session| session.coordinator.clone());
    }
    if let Some(bound_session) = scope
        .coordinator
        .as_deref()
        .and_then(|coordinator| stored_session_for_coordinator(coordinator, stored_session))
    {
        scope.tenant = bound_session.tenant.clone();
        scope.project = bound_session.project.clone();
        scope.user = bound_session.user.clone();
    }
}

pub(crate) fn process_list_report_with_session(
    mut args: ProcessListArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    hydrate_process_scope(&mut args.scope, stored_session);
    let Some(coordinator) = &args.scope.coordinator else {
        return Ok(json!({
            "command": "process list",
            "status": "requires_coordinator",
            "processes": [],
        }));
    };
    let mut session = JsonLineSession::connect(coordinator)?;
    let response = session.request(authenticated_or_local_trusted_request(
        coordinator,
        stored_session,
        CoordinatorRequest::ListProcesses {
            tenant: args.scope.tenant.clone(),
            project: args.scope.project.clone(),
            actor_user: args.scope.user.clone(),
        },
    )?)?;
    let processes = match &response {
        CoordinatorResponse::ProcessStatuses { processes, .. } => processes,
        _ => anyhow::bail!("coordinator returned an unexpected process-list response"),
    };
    Ok(json!({
        "command": "process list",
        "status": "ok",
        "coordinator": coordinator,
        "tenant": args.scope.tenant,
        "project": args.scope.project,
        "user": args.scope.user,
        "processes": processes,
        "response": serde_json::to_value(response)?,
        "coordinator_session_requests": session.requests(),
    }))
}

#[cfg(test)]
pub(crate) fn process_status_report(args: ProcessStatusArgs) -> Result<Value> {
    process_status_report_with_session(args, None)
}

pub(crate) fn process_status_report_with_session(
    mut args: ProcessStatusArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    hydrate_process_scope(&mut args.scope, stored_session);
    let live = process_list_report_with_session(
        ProcessListArgs {
            scope: args.scope.clone(),
        },
        stored_session,
    )?;
    let live_process = live
        .get("processes")
        .and_then(Value::as_array)
        .and_then(|processes| {
            processes.iter().find(|process| {
                process.get("process").and_then(Value::as_str) == Some(args.process.as_str())
            })
        })
        .cloned();
    let events = list_task_events_if_available_with_session(
        args.scope.coordinator.as_deref(),
        &args.scope,
        Some(args.process.clone()),
        stored_session,
    )?;
    let current_tasks = task_summaries(events.as_ref());
    let current_task_count = current_tasks.as_array().map(Vec::len).unwrap_or(0);
    let historical_state = process_state_from_tasks(events.as_ref());
    let state = live_process
        .as_ref()
        .and_then(|process| process.get("state"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            if live.get("status").and_then(Value::as_str) == Some("ok") {
                "not_active".to_owned()
            } else if events.is_some() {
                historical_state.to_owned()
            } else {
                "unknown_without_coordinator".to_owned()
            }
        });
    Ok(json!({
        "command": "process status",
        "process": args.process,
        "state": state,
        "live_process": live_process,
        "started_entrypoint": "unknown_from_task_events",
        "current_task_count": current_task_count,
        "current_tasks": current_tasks,
        "debug_state": {
            "frozen": null,
            "status": "unknown_from_cli_task_events"
        },
        "events": events,
    }))
}

#[cfg(test)]
pub(crate) fn process_restart_report(args: ProcessRestartArgs) -> Result<Value> {
    process_restart_report_with_session(args, None)
}

pub(crate) fn process_restart_report_with_session(
    mut args: ProcessRestartArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    hydrate_process_scope(&mut args.scope, stored_session);
    if !args.yes {
        return Ok(confirmation_required_report(
            "process restart",
            "restart_virtual_process",
            json!({
                "coordinator": args.scope.coordinator,
                "tenant": args.scope.tenant,
                "project": args.scope.project,
                "process": args.process,
            }),
            format!(
                "clusterflux process restart --process {} --yes",
                args.process
            ),
        ));
    }
    if let Some(coordinator) = &args.scope.coordinator {
        let mut session = JsonLineSession::connect(coordinator)?;
        let response = session.request(authenticated_or_local_trusted_request(
            coordinator,
            stored_session,
            CoordinatorRequest::StartProcess {
                tenant: args.scope.tenant.clone(),
                project: args.scope.project.clone(),
                actor_user: Some(args.scope.user.clone()),
                actor_agent: None,
                agent_public_key_fingerprint: None,
                agent_signature: None,
                process: args.process.clone(),
                launch_attempt: None,
                restart: true,
            },
        )?)?;
        let restart_request = process_restart_request_summary(&response, !args.yes);
        return Ok(json!({
            "command": "process restart",
            "coordinator": coordinator,
            "process": args.process,
            "requires_confirmation": !args.yes,
            "restart_request": restart_request,
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "process restart",
        "status": "requires_coordinator",
        "requires_confirmation": !args.yes,
        "process": args.process,
        "restart_request": {
            "status": "requires_coordinator",
            "operation": "restart_virtual_process",
            "explicit_user_action": true,
        },
    }))
}

pub(crate) fn process_cancel_report(args: ProcessCancelArgs) -> Result<Value> {
    process_cancel_report_with_session(args, None)
}

pub(crate) fn process_cancel_report_with_session(
    mut args: ProcessCancelArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    hydrate_process_scope(&mut args.scope, stored_session);
    if !args.yes {
        return Ok(confirmation_required_report(
            "process cancel",
            "cancel_virtual_process",
            json!({
                "coordinator": args.scope.coordinator,
                "tenant": args.scope.tenant,
                "project": args.scope.project,
                "process": args.process,
                "node": args.node,
                "task": args.task,
            }),
            format!(
                "clusterflux process cancel --process {} --yes",
                args.process
            ),
        ));
    }
    if let Some(coordinator) = &args.scope.coordinator {
        let mut session = JsonLineSession::connect(coordinator)?;
        let response = session.request(authenticated_or_local_trusted_request(
            coordinator,
            stored_session,
            CoordinatorRequest::CancelProcess {
                tenant: args.scope.tenant.clone(),
                project: args.scope.project.clone(),
                actor_user: args.scope.user.clone(),
                process: args.process.clone(),
            },
        )?)?;
        let cancel_request = process_cancel_request_summary(&response, !args.yes);
        return Ok(json!({
            "command": "process cancel",
            "coordinator": coordinator,
            "requires_confirmation": !args.yes,
            "process": args.process,
            "node": args.node,
            "task": args.task,
            "cancel_request": cancel_request,
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "process cancel",
        "status": "requires_coordinator",
        "requires_confirmation": !args.yes,
        "process": args.process,
        "node": args.node,
        "task": args.task,
        "cancel_request": {
            "status": "requires_coordinator",
            "operation": "cancel_virtual_process",
            "whole_process_cancel_available": true,
            "explicit_user_action": true,
        },
    }))
}

pub(crate) fn process_abort_report_with_session(
    mut args: ProcessAbortArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    hydrate_process_scope(&mut args.scope, stored_session);
    if !args.yes {
        return Ok(confirmation_required_report(
            "process abort",
            "abort_virtual_process",
            json!({
                "coordinator": args.scope.coordinator,
                "tenant": args.scope.tenant,
                "project": args.scope.project,
                "process": args.process,
            }),
            format!("clusterflux process abort --process {} --yes", args.process),
        ));
    }
    let Some(coordinator) = &args.scope.coordinator else {
        return Ok(json!({
            "command": "process abort",
            "status": "requires_coordinator",
            "process": args.process,
            "requires_confirmation": false,
        }));
    };
    let mut session = JsonLineSession::connect(coordinator)?;
    let response = session.request(authenticated_or_local_trusted_request(
        coordinator,
        stored_session,
        CoordinatorRequest::AbortProcess {
            tenant: args.scope.tenant.clone(),
            project: args.scope.project.clone(),
            actor_user: args.scope.user.clone(),
            process: args.process.clone(),
            launch_attempt: None,
        },
    )?)?;
    let accepted = matches!(&response, CoordinatorResponse::ProcessAborted { .. });
    if !accepted {
        anyhow::bail!("coordinator returned an unexpected process-abort response");
    }
    Ok(json!({
        "command": "process abort",
        "status": "aborted",
        "coordinator": coordinator,
        "process": args.process,
        "requires_confirmation": false,
        "abort_request": {
            "accepted": accepted,
            "operation": "abort_virtual_process",
            "forced": true,
            "cooperative": false,
            "process_slot_released": true,
        },
        "response": serde_json::to_value(response)?,
        "coordinator_session_requests": session.requests(),
    }))
}
