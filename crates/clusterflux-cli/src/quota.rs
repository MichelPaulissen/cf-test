use std::path::PathBuf;

use anyhow::Result;
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};
use serde_json::{json, Value};

use crate::client::{
    authenticated_or_local_trusted_request, list_attached_nodes_if_available_with_session,
    list_task_events_if_available_with_session, stored_session_for_coordinator, JsonLineSession,
};
use crate::config::{effective_project_scope, read_cli_session, read_project_config};
use crate::process_events::{quota_current_usage, quota_limits_value, quota_next_blocked_action};
use crate::QuotaStatusArgs;

pub(crate) fn quota_status_report(args: QuotaStatusArgs, cwd: PathBuf) -> Result<Value> {
    let config = read_project_config(&cwd)?;
    let stored_session = read_cli_session(&cwd)?;
    let mut effective_scope = effective_project_scope(&args.scope, config.as_ref());
    if effective_scope.coordinator.is_none() {
        effective_scope.coordinator = stored_session
            .as_ref()
            .filter(|session| session.session_secret.is_some())
            .map(|session| session.coordinator.clone());
    }
    if let Some(bound_session) = effective_scope
        .coordinator
        .as_deref()
        .and_then(|coordinator| {
            stored_session_for_coordinator(coordinator, stored_session.as_ref())
        })
    {
        effective_scope.tenant = bound_session.tenant.clone();
        effective_scope.project = bound_session.project.clone();
        effective_scope.user = bound_session.user.clone();
    }
    let coordinator = effective_scope.coordinator.clone();
    let attached_nodes = list_attached_nodes_if_available_with_session(
        coordinator.as_deref(),
        &effective_scope,
        stored_session.as_ref(),
    )?;
    let task_events = list_task_events_if_available_with_session(
        coordinator.as_deref(),
        &effective_scope,
        None,
        stored_session.as_ref(),
    )?;
    let quota_status = if let Some(coordinator) = coordinator.as_deref() {
        let mut session = JsonLineSession::connect(coordinator)?;
        Some(session.request(authenticated_or_local_trusted_request(
            coordinator,
            stored_session.as_ref(),
            CoordinatorRequest::QuotaStatus {
                tenant: effective_scope.tenant.clone(),
                project: effective_scope.project.clone(),
                actor_user: effective_scope.user.clone(),
            },
        )?)?)
    } else {
        None
    };
    let mut current_usage = quota_current_usage(&attached_nodes, task_events.as_ref());
    if let (Some(object), Some(status)) = (current_usage.as_object_mut(), quota_status.as_ref()) {
        let CoordinatorResponse::QuotaStatus {
            usage,
            window_started_epoch_seconds,
            projects_current,
            node_identities_current,
            active_processes_current,
            ..
        } = status
        else {
            anyhow::bail!("coordinator returned an unexpected quota response");
        };
        object.insert(
            "scoped_resource_usage".to_owned(),
            serde_json::to_value(usage)?,
        );
        object.insert(
            "window_started_epoch_seconds".to_owned(),
            serde_json::to_value(window_started_epoch_seconds)?,
        );
        object.insert(
            "node_identities".to_owned(),
            serde_json::to_value(node_identities_current)?,
        );
        object.insert(
            "projects".to_owned(),
            serde_json::to_value(projects_current)?,
        );
        object.insert(
            "active_processes".to_owned(),
            serde_json::to_value(active_processes_current)?,
        );
    }
    let (limits, window_seconds, quota_tier) = match quota_status.as_ref() {
        Some(CoordinatorResponse::QuotaStatus {
            limits,
            window_seconds,
            policy_label,
            projects_maximum,
            node_identities_maximum,
            active_processes_maximum,
            ..
        }) => (
            {
                let mut limits = serde_json::to_value(&limits.limits)?;
                if let Some(object) = limits.as_object_mut() {
                    object.insert(
                        "node_identities".to_owned(),
                        serde_json::to_value(node_identities_maximum)?,
                    );
                    object.insert(
                        "projects".to_owned(),
                        serde_json::to_value(projects_maximum)?,
                    );
                    object.insert(
                        "active_processes".to_owned(),
                        serde_json::to_value(active_processes_maximum)?,
                    );
                }
                limits
            },
            serde_json::to_value(window_seconds)?,
            serde_json::to_value(policy_label)?,
        ),
        Some(_) => anyhow::bail!("coordinator returned an unexpected quota response"),
        None => (quota_limits_value(), Value::Null, Value::Null),
    };
    Ok(json!({
        "command": "quota status",
        "tenant": effective_scope.tenant,
        "project": effective_scope.project,
        "user": effective_scope.user,
        "coordinator": coordinator,
        "project_config": config,
        "policy_surface": "generic public quota categories; hosted tuning is coordinator-defined",
        "limits": limits,
        "window_seconds": window_seconds,
        "current_usage": current_usage,
        "attached_nodes": attached_nodes,
        "task_events": task_events,
        "next_blocked_action": quota_next_blocked_action(&current_usage),
        "quota_configuration_source": if quota_status.is_some() { "coordinator" } else { "unavailable_offline" },
        "quota_tier": quota_tier,
        "sensitive_abuse_heuristics_exposed": false,
        "quota_response": quota_status,
    }))
}
