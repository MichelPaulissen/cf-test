use std::path::Path;

use clusterflux_protocol::CoordinatorResponse;
use serde_json::{json, Value};

use crate::errors::{
    cli_error_summary, cli_error_summary_for_category, cli_error_summary_with_default,
    message_mentions_locality_failure,
};

fn task_event_values(task_events: Option<&Value>) -> Vec<&Value> {
    task_events
        .and_then(|task_events| task_events.pointer("/response/events"))
        .and_then(Value::as_array)
        .map(|events| events.iter().collect())
        .unwrap_or_default()
}

fn event_string(event: &Value, field: &str) -> Option<String> {
    event.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn event_u64(event: &Value, field: &str) -> Option<u64> {
    event.get(field).and_then(Value::as_u64)
}

pub(crate) fn task_summaries(task_events: Option<&Value>) -> Value {
    Value::Array(
        task_event_values(task_events)
            .into_iter()
            .map(|event| {
                let task = event_string(event, "task").unwrap_or_else(|| "unknown".to_owned());
                let terminal_state =
                    event_string(event, "terminal_state").unwrap_or_else(|| "unknown".to_owned());
                let node = event_string(event, "node");
                let placement = event.get("placement");
                let placement_reasons = placement
                    .and_then(|placement| placement.get("reasons"))
                    .cloned()
                    .unwrap_or_else(|| json!([]));
                let placement_score = placement
                    .and_then(|placement| placement.get("score"))
                    .cloned()
                    .unwrap_or(Value::Null);
                let failure_reason = task_failure_reason(event);
                let locality_failure = task_locality_failure_from_reason(&failure_reason);
                let machine_error = task_failure_machine_error_from_reason(event, &failure_reason);
                json!({
                    "process": event_string(event, "process"),
                    "task": task,
                    "state": terminal_state,
                    "environment": event.get("environment").cloned().unwrap_or_else(|| json!("unknown_from_task_event")),
                    "environment_digest": event.get("environment_digest").cloned().unwrap_or(Value::Null),
                    "node_placement": {
                        "node": node,
                        "source": "coordinator_task_event",
                        "score": placement_score,
                        "reasons": placement_reasons,
                        "explanation_available": placement.is_some(),
                    },
                    "failure_reason": failure_reason,
                    "locality_failure": locality_failure,
                    "machine_error": machine_error,
                    "stdout_bytes": event_u64(event, "stdout_bytes").unwrap_or(0),
                    "stderr_bytes": event_u64(event, "stderr_bytes").unwrap_or(0),
                })
            })
            .collect(),
    )
}

fn task_failure_reason(event: &Value) -> Value {
    match event.get("terminal_state").and_then(Value::as_str) {
        Some("failed") => {
            if let Some(stderr) = event.get("stderr_tail").and_then(Value::as_str) {
                if !stderr.is_empty() {
                    return json!(redact_secret_like_text(stderr).0);
                }
            }
            if let Some(status_code) = event.get("status_code").and_then(Value::as_i64) {
                return json!(format!("task exited with status {status_code}"));
            }
            json!("task failed")
        }
        Some("cancelled") => json!("task cancelled"),
        _ => Value::Null,
    }
}

fn task_failure_machine_error_from_reason(event: &Value, reason: &Value) -> Value {
    match event.get("terminal_state").and_then(Value::as_str) {
        Some("failed") => {
            let reason = reason.as_str().unwrap_or("task failed").to_owned();
            let mut summary = cli_error_summary_with_default(&reason, "program");
            if let Some(object) = summary.as_object_mut() {
                if message_mentions_locality_failure(&reason.to_ascii_lowercase()) {
                    object.insert("locality_failure".to_owned(), json!(true));
                    object.insert(
                        "next_actions".to_owned(),
                        json!(locality_failure_next_actions(&reason)),
                    );
                }
            }
            summary
        }
        Some("cancelled") => cli_error_summary_for_category("program", "task cancelled"),
        _ => Value::Null,
    }
}

fn task_locality_failure_from_reason(reason: &Value) -> Value {
    let Some(reason) = reason.as_str() else {
        return Value::Null;
    };
    let lower = reason.to_ascii_lowercase();
    if !message_mentions_locality_failure(&lower) {
        return Value::Null;
    }
    let affected_data = if lower.contains("source snapshot") {
        "source_snapshot"
    } else if lower.contains("artifact") {
        "artifact"
    } else {
        "direct_transfer"
    };
    json!({
        "category": "connectivity",
        "affected_data": affected_data,
        "reason": reason,
        "coordinator_bulk_relay_used": false,
        "safe_failure": true,
        "safe_next_actions": locality_failure_next_actions(reason),
    })
}

fn locality_failure_next_actions(reason: &str) -> Vec<&'static str> {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("source snapshot") {
        return vec![
            "attach or select a node that already has the required source snapshot",
            "rerun source preparation on an attached node",
            "restore direct node-to-node connectivity and retry",
            "do not rely on coordinator bulk source relay",
        ];
    }
    if lower.contains("artifact") {
        return vec![
            "attach or select a node that already has the required artifact",
            "explicitly export or download the artifact before retrying",
            "restore direct node-to-node connectivity and retry",
            "do not rely on coordinator bulk artifact relay",
        ];
    }
    vec![
        "check node direct connectivity and NAT traversal",
        "attach a node with the needed source/artifact locality",
        "retry after node connectivity is restored",
        "do not rely on coordinator bulk relay",
    ]
}

pub(crate) fn process_state_from_tasks(task_events: Option<&Value>) -> &'static str {
    let events = task_event_values(task_events);
    if events.is_empty() {
        return "no_tasks_observed";
    }
    if events.iter().any(|event| {
        event
            .get("terminal_state")
            .and_then(Value::as_str)
            .is_some_and(|state| state == "failed")
    }) {
        return "has_failed_tasks";
    }
    if events.iter().any(|event| {
        event
            .get("terminal_state")
            .and_then(Value::as_str)
            .is_some_and(|state| state == "cancelled")
    }) {
        return "has_cancelled_tasks";
    }
    if events.iter().all(|event| {
        event
            .get("terminal_state")
            .and_then(Value::as_str)
            .is_some_and(|state| state == "completed")
    }) {
        return "completed_tasks_observed";
    }
    "tasks_observed"
}

pub(crate) fn log_entries(task_events: Option<&Value>, task_filter: Option<&str>) -> Value {
    Value::Array(
        task_event_values(task_events)
            .into_iter()
            .filter(|event| {
                task_filter.is_none_or( |task_filter| {
                    event
                        .get("task")
                        .and_then(Value::as_str)
                        .is_some_and(|task| task == task_filter)
                })
            })
            .map(|event| {
                let stdout_tail = event
                    .get("stdout_tail")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let stderr_tail = event
                    .get("stderr_tail")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let (stdout_tail, stdout_tail_redacted) = redact_secret_like_text(stdout_tail);
                let (stderr_tail, stderr_tail_redacted) = redact_secret_like_text(stderr_tail);
                json!({
                    "process": event_string(event, "process"),
                    "task": event_string(event, "task"),
                    "node": event_string(event, "node"),
                    "stdout_bytes": event_u64(event, "stdout_bytes").unwrap_or(0),
                    "stderr_bytes": event_u64(event, "stderr_bytes").unwrap_or(0),
                    "stdout_tail": stdout_tail,
                    "stderr_tail": stderr_tail,
                    "stdout_truncated": event.get("stdout_truncated").and_then(Value::as_bool).unwrap_or(false),
                    "stderr_truncated": event.get("stderr_truncated").and_then(Value::as_bool).unwrap_or(false),
                    "capped": true,
                    "secret_like_values_redacted": stdout_tail_redacted || stderr_tail_redacted,
                    "redacted_fields": redacted_log_fields(stdout_tail_redacted, stderr_tail_redacted),
                })
            })
            .collect(),
    )
}

fn redacted_log_fields(
    stdout_tail_redacted: bool,
    stderr_tail_redacted: bool,
) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if stdout_tail_redacted {
        fields.push("stdout_tail");
    }
    if stderr_tail_redacted {
        fields.push("stderr_tail");
    }
    fields
}

fn redact_secret_like_text(text: &str) -> (String, bool) {
    let markers = [
        "access_token=",
        "access_token:",
        "refresh_token=",
        "refresh_token:",
        "id_token=",
        "id_token:",
        "api_key=",
        "api_key:",
        "api-key=",
        "api-key:",
        "token=",
        "token:",
        "secret=",
        "secret:",
        "password=",
        "password:",
        "passwd=",
        "passwd:",
        "bearer ",
    ];
    let mut output = text.to_owned();
    let mut redacted = false;
    for marker in markers {
        let (updated, changed) = redact_marker_values(output, marker);
        output = updated;
        redacted |= changed;
    }
    (output, redacted)
}

fn redact_marker_values(mut text: String, marker: &str) -> (String, bool) {
    let mut changed = false;
    let mut search_start = 0;
    loop {
        let lower = text.to_ascii_lowercase();
        let Some(relative) = lower[search_start..].find(marker) else {
            break;
        };
        let value_start = search_start + relative + marker.len();
        let value_end = text[value_start..]
            .char_indices()
            .find_map(|(offset, character)| {
                (character.is_whitespace()
                    || matches!(
                        character,
                        '&' | '"' | '\'' | '`' | '<' | '>' | ',' | ';' | ')' | ']'
                    ))
                .then_some(value_start + offset)
            })
            .unwrap_or(text.len());
        if value_start == value_end {
            search_start = value_end;
            if search_start >= text.len() {
                break;
            }
            continue;
        }
        if text[value_start..value_end].starts_with("[redacted") {
            search_start = value_end;
            if search_start >= text.len() {
                break;
            }
            continue;
        }
        text.replace_range(value_start..value_end, "[redacted]");
        changed = true;
        search_start = value_start + "[redacted]".len();
        if search_start >= text.len() {
            break;
        }
    }
    (text, changed)
}

pub(crate) fn artifact_summaries(task_events: Option<&Value>) -> Value {
    Value::Array(
        task_event_values(task_events)
            .into_iter()
            .filter_map(|event| {
                let path = event.get("artifact_path").and_then(Value::as_str)?;
                let node = event_string(event, "node");
                Some(json!({
                    "artifact": artifact_name_from_path(path),
                    "path": path,
                    "producer_task": event_string(event, "task"),
                    "producer_node": node,
                    "process": event_string(event, "process"),
                    "digest": event.get("artifact_digest").cloned().unwrap_or(Value::Null),
                    "size_bytes": event.get("artifact_size_bytes").cloned().unwrap_or(Value::Null),
                    "state": if event.get("artifact_digest").is_some() { "metadata_flushed" } else { "metadata_without_digest" },
                    "known_locations": node.into_iter().collect::<Vec<_>>(),
                    "durable_storage": false,
                }))
            })
            .collect(),
    )
}

fn artifact_name_from_path(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_owned()
}

fn response_error_message(response: &CoordinatorResponse, fallback: &str) -> String {
    match response {
        CoordinatorResponse::Error { error } => error.message.clone(),
        _ => fallback.to_owned(),
    }
}

pub(crate) fn artifact_response_machine_error(
    response: &CoordinatorResponse,
    fallback: &str,
    default_category: &'static str,
) -> Value {
    match response {
        CoordinatorResponse::Error { error } => {
            crate::errors::cli_error_summary_for_api_error(error)
        }
        _ => cli_error_summary_with_default(fallback, default_category),
    }
}

fn response_machine_error(response: &CoordinatorResponse, fallback: &str) -> Value {
    match response {
        CoordinatorResponse::Error { error } => {
            crate::errors::cli_error_summary_for_api_error(error)
        }
        _ => cli_error_summary(fallback),
    }
}

pub(crate) fn process_restart_request_summary(
    response: &CoordinatorResponse,
    requires_confirmation: bool,
) -> Value {
    let CoordinatorResponse::ProcessStarted { process, epoch, .. } = response else {
        let message = response_error_message(
            response,
            "coordinator returned an unexpected process-restart response",
        );
        return json!({
            "status": "error",
            "operation": "restart_virtual_process",
            "accepted": false,
            "requires_confirmation": requires_confirmation,
            "explicit_user_action": true,
            "error": message,
            "machine_error": response_machine_error(response, &message),
        });
    };
    json!({
        "status": "process_started",
        "operation": "restart_virtual_process",
        "accepted": true,
        "process": process,
        "coordinator_epoch": epoch,
        "requires_confirmation": requires_confirmation,
        "explicit_user_action": true,
        "website_required": false,
        "single_active_process_boundary": true,
    })
}

pub(crate) fn process_cancel_request_summary(
    response: &CoordinatorResponse,
    requires_confirmation: bool,
) -> Value {
    let CoordinatorResponse::ProcessCancellationRequested {
        process,
        cancelled_tasks,
        affected_nodes,
    } = response
    else {
        let message = response_error_message(
            response,
            "coordinator returned an unexpected process-cancel response",
        );
        return json!({
            "status": "error",
            "operation": "cancel_virtual_process",
            "accepted": false,
            "requires_confirmation": requires_confirmation,
            "explicit_user_action": true,
            "whole_process_cancel_available": true,
            "error": message,
            "machine_error": response_machine_error(response, &message),
        });
    };
    json!({
        "status": "process_cancellation_requested",
        "operation": "cancel_virtual_process",
        "accepted": true,
        "process": process,
        "cancelled_task_count": cancelled_tasks.len(),
        "cancelled_tasks": cancelled_tasks,
        "affected_nodes": affected_nodes,
        "requires_confirmation": requires_confirmation,
        "explicit_user_action": true,
        "website_required": false,
        "whole_process_cancel_available": true,
        "node_must_poll_task_control": true,
        "new_task_launches_blocked": true,
        "surviving_state_visibility": "task and artifact state remains visible after terminal task events are reported",
    })
}

pub(crate) fn task_restart_request_summary(
    response: &CoordinatorResponse,
    requires_confirmation: bool,
) -> Value {
    let CoordinatorResponse::TaskRestart {
        process,
        task,
        accepted,
        clean_boundary_available,
        active_task,
        completed_event_observed,
        requires_whole_process_restart,
        message,
        audit_event,
        charged_debug_read_bytes,
        used_debug_read_bytes,
        ..
    } = response
    else {
        let message = response_error_message(
            response,
            "coordinator returned an unexpected task-restart response",
        );
        return json!({
            "status": "error",
            "operation": "restart_selected_task",
            "accepted": false,
            "requires_confirmation": requires_confirmation,
            "explicit_user_action": true,
            "clean_boundary_required": true,
            "error": message,
            "machine_error": response_machine_error(response, &message),
        });
    };
    json!({
        "status": "task_restart",
        "operation": "restart_selected_task",
        "accepted": accepted,
        "process": process,
        "task": task,
        "requires_confirmation": requires_confirmation,
        "explicit_user_action": true,
        "clean_boundary_required": true,
        "clean_boundary_available": clean_boundary_available,
        "active_task": active_task,
        "completed_event_observed": completed_event_observed,
        "requires_whole_process_restart": requires_whole_process_restart,
        "message": message,
        "audit_event": audit_event,
        "charged_debug_read_bytes": charged_debug_read_bytes,
        "used_debug_read_bytes": used_debug_read_bytes,
        "debug_reads_quota_limited": true,
        "website_required": false,
    })
}

pub(crate) fn artifact_download_session_summary(response: &CoordinatorResponse) -> Value {
    let CoordinatorResponse::ArtifactDownloadLink { link } = response else {
        let message = response_error_message(response, "coordinator rejected artifact download");
        return json!({
            "status": "error",
            "link_issued": false,
            "explicit_user_action_required": true,
            "error": message.clone(),
            "machine_error": artifact_response_machine_error(response, &message, "connectivity"),
        });
    };
    json!({
        "status": "download_link_issued",
        "link_issued": true,
        "explicit_user_action_required": true,
        "coordinator_preflight": "completed_before_link_issued",
        "tenant": link.tenant,
        "project": link.project,
        "process": link.process,
        "artifact": link.artifact,
        "actor": link.actor,
        "source": link.source,
        "url_path": link.url_path,
        "expires_at_epoch_seconds": link.expires_at_epoch_seconds,
        "max_bytes": link.max_bytes,
        "token_material_returned": false,
        "scoped_token_digest_present": true,
        "policy_context_digest_present": true,
        "authorization_required": true,
        "short_lived": true,
        "guessable_public_url": false,
        "cross_tenant_usable": false,
        "unauthorized_project_usable": false,
        "default_durable_store_assumed": false,
    })
}

pub(crate) fn artifact_download_grant_disclosures(response: &CoordinatorResponse) -> Value {
    let CoordinatorResponse::ArtifactDownloadLink { link } = response else {
        return json!([]);
    };
    json!([{
        "grant": "artifact_download",
        "description": "download scoped artifact bytes to the requesting machine",
        "risk": "authorized artifact bytes leave the retaining node or explicit storage through an explicit download/export operation",
        "coordinator_policy_limited": true,
        "authorization_required": true,
        "explicit_user_action_required": true,
        "tenant": link.tenant,
        "project": link.project,
        "process": link.process,
        "artifact": link.artifact,
        "actor": link.actor,
        "source": link.source,
        "max_bytes": link.max_bytes,
        "expires_at_epoch_seconds": link.expires_at_epoch_seconds,
        "short_lived": true,
        "scoped_token_digest_present": true,
        "token_material_returned": false,
        "guessable_public_url": false,
        "cross_tenant_reuse_allowed": false,
        "unauthorized_project_reuse_allowed": false,
        "default_durable_store_assumed": false,
        "external_website_required": false,
    }])
}

pub(crate) fn artifact_export_plan_summary(
    response: &CoordinatorResponse,
    to: Option<&Path>,
) -> Value {
    let CoordinatorResponse::ArtifactExport {
        transfer,
        receiver_node,
        artifact_size_bytes,
        already_present,
    } = response
    else {
        let message = response_error_message(response, "coordinator rejected artifact export");
        return json!({
            "status": "error",
            "explicit_user_action": true,
            "local_path": to,
            "local_bytes_written_by_cli": false,
            "default_durable_store_assumed": false,
            "error": message.clone(),
            "machine_error": artifact_response_machine_error(response, &message, "connectivity"),
        });
    };
    json!({
        "status": if *already_present {
            "already_present"
        } else {
            "transfer_created"
        },
        "explicit_user_action": true,
        "local_path": to,
        "local_bytes_written_by_cli": false,
        "writes_require_data_plane_followup": true,
        "default_durable_store_assumed": false,
        "artifact_size_bytes": artifact_size_bytes,
        "transfer_id": transfer.as_ref().map(|transfer| &transfer.transfer_id),
        "transfer_state": transfer.as_ref().map(|transfer| &transfer.state),
        "source_node": transfer.as_ref().map(|transfer| &transfer.source_node),
        "receiver_node": receiver_node,
        "path_kind": transfer.as_ref().map(|transfer| &transfer.path_kind),
        "artifact": transfer.as_ref().map(|transfer| &transfer.artifact),
        "tenant": transfer.as_ref().map(|transfer| &transfer.tenant),
        "project": transfer.as_ref().map(|transfer| &transfer.project),
        "process": transfer.as_ref().map(|transfer| &transfer.process),
        "coordinator_bulk_relay_allowed": false,
        "authorization_material_returned": false,
    })
}

pub(crate) fn task_event_count(task_events: Option<&Value>) -> usize {
    task_events
        .and_then(|task_events| task_events.pointer("/response/events"))
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

pub(crate) fn project_quota_posture(attached_nodes: &Value, task_events: Option<&Value>) -> Value {
    let current_usage = quota_current_usage(attached_nodes, task_events);
    let next_blocked_action = quota_next_blocked_action(&current_usage);
    json!({
        "source": "cli_project_status_summary",
        "current_usage": current_usage,
        "limits": quota_limits_value(),
        "next_blocked_action": next_blocked_action,
        "sensitive_abuse_heuristics_exposed": false,
    })
}

pub(crate) fn quota_current_usage(attached_nodes: &Value, task_events: Option<&Value>) -> Value {
    let attached_node_count = attached_nodes
        .get("count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let online_node_count = attached_nodes
        .get("online")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    json!({
        "attached_nodes": attached_node_count,
        "online_nodes": online_node_count,
        "observed_task_events": task_event_count(task_events),
        "artifact_download_bytes": 0,
        "hosted_wasm_processes": 0,
    })
}

pub(crate) fn quota_limits_value() -> Value {
    json!({
        "source": "coordinator",
        "configured": false,
        "message": "connect to the selected coordinator to read its scoped quota configuration",
    })
}

pub(crate) fn quota_next_blocked_action(current_usage: &Value) -> Value {
    if current_usage
        .get("online_nodes")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        == 0
    {
        return json!({
            "action": "node_work_requires_online_attached_node",
            "category": "capability",
            "quota_related": false,
            "message": "no online attached node is visible for work that requires a user node",
            "machine_error": cli_error_summary_for_category(
                "capability",
                "no online attached node is visible for work that requires a user node"
            )
        });
    }
    Value::Null
}
