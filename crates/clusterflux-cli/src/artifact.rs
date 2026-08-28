use anyhow::Result;
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};
use serde_json::{json, Value};

use crate::client::{
    authenticated_or_local_trusted_request, list_task_events_if_available_with_session,
    JsonLineSession,
};
use crate::config::StoredCliSession;
use crate::errors::cli_error_summary_for_category;
use crate::process::hydrate_process_scope;
use crate::process_events::{
    artifact_download_grant_disclosures, artifact_download_session_summary,
    artifact_export_plan_summary, artifact_response_machine_error, artifact_summaries,
};
use crate::{ArtifactDownloadArgs, ArtifactExportArgs, ArtifactListArgs};

#[cfg(test)]
pub(crate) fn artifact_list_report(args: ArtifactListArgs) -> Result<Value> {
    artifact_list_report_with_session(args, None)
}

pub(crate) fn artifact_list_report_with_session(
    mut args: ArtifactListArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    hydrate_process_scope(&mut args.scope, stored_session);
    let events = list_task_events_if_available_with_session(
        args.scope.coordinator.as_deref(),
        &args.scope,
        args.process.clone(),
        stored_session,
    )?;
    let artifacts = artifact_summaries(events.as_ref());
    Ok(json!({
        "command": "artifact list",
        "process": args.process,
        "source": "task_events",
        "artifacts": artifacts,
        "default_durable_store_assumed": false,
        "events": events,
    }))
}

#[cfg(test)]
pub(crate) fn artifact_download_report(args: ArtifactDownloadArgs) -> Result<Value> {
    artifact_download_report_with_session(args, None)
}

pub(crate) fn artifact_download_report_with_session(
    mut args: ArtifactDownloadArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    hydrate_process_scope(&mut args.scope, stored_session);
    if let Some(coordinator) = &args.scope.coordinator {
        let mut session = JsonLineSession::connect(coordinator)?;
        let response = session.request(authenticated_or_local_trusted_request(
            coordinator,
            stored_session,
            CoordinatorRequest::CreateArtifactDownloadLink {
                tenant: args.scope.tenant.clone(),
                project: args.scope.project.clone(),
                actor_user: args.scope.user.clone(),
                artifact: args.artifact.clone(),
                max_bytes: args.max_bytes,
                ttl_seconds: 15 * 60,
            },
        )?)?;
        let download_session = artifact_download_session_summary(&response);
        let grant_disclosures = artifact_download_grant_disclosures(&response);
        let local_download = match &args.to {
            Some(path) if matches!(&response, CoordinatorResponse::ArtifactDownloadLink { .. }) => {
                json!({
                    "status": "direct_node_export_required",
                    "local_path": path,
                    "local_bytes_written_by_cli": false,
                    "machine_error": cli_error_summary_for_category(
                        "program",
                        "coordinator artifact-byte downloads were retired; use artifact export --receiver-node so bytes move directly over Iroh"
                    ),
                })
            }
            Some(path) => json!({
                "status": "download_link_failed",
                "local_path": path,
                "local_bytes_written_by_cli": false,
                "machine_error": artifact_response_machine_error(
                    &response,
                    "coordinator rejected artifact download",
                    "connectivity"
                ),
            }),
            None => Value::Null,
        };
        return Ok(json!({
            "command": "artifact download",
            "coordinator": coordinator,
            "artifact": args.artifact,
            "max_bytes": args.max_bytes,
            "to": args.to,
            "download_session": download_session,
            "local_download": local_download,
            "grant_disclosures": grant_disclosures,
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "artifact download",
        "status": "requires_coordinator",
        "artifact": args.artifact,
        "max_bytes": args.max_bytes,
        "to": args.to,
        "download_session": {
            "status": "requires_coordinator",
            "link_issued": false,
            "explicit_user_action_required": true,
            "machine_error": cli_error_summary_for_category(
                "connectivity",
                "artifact download requires a coordinator"
            ),
        },
        "grant_disclosures": [],
    }))
}

#[cfg(test)]
pub(crate) fn artifact_export_report(args: ArtifactExportArgs) -> Result<Value> {
    artifact_export_report_with_session(args, None)
}

pub(crate) fn artifact_export_report_with_session(
    mut args: ArtifactExportArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    hydrate_process_scope(&mut args.scope, stored_session);
    if let Some(coordinator) = &args.scope.coordinator {
        let mut session = JsonLineSession::connect(coordinator)?;
        let response = session.request(authenticated_or_local_trusted_request(
            coordinator,
            stored_session,
            CoordinatorRequest::ExportArtifactToNode {
                tenant: args.scope.tenant.clone(),
                project: args.scope.project.clone(),
                actor_user: args.scope.user.clone(),
                artifact: args.artifact.clone(),
                receiver_node: args.receiver_node.clone(),
            },
        )?)?;
        let mut export_plan = artifact_export_plan_summary(&response, args.to.as_deref());
        let local_export = if matches!(&response, CoordinatorResponse::ArtifactExport { .. }) {
            json!({
                "status": "node_transfer_submitted",
                "explicit_user_action": true,
                "local_path": &args.to,
                "local_bytes_written_by_cli": false,
                "content_bytes_available": false,
                "machine_error": Value::Null,
            })
        } else {
            json!({
                "status": "skipped",
                "explicit_user_action": true,
                "local_path": &args.to,
                "local_bytes_written_by_cli": false,
                "machine_error": artifact_response_machine_error(
                    &response,
                    "coordinator rejected artifact export",
                    "connectivity"
                ),
            })
        };
        apply_local_export_summary(&mut export_plan, &local_export);
        let grant_disclosures = local_export
            .get("grant_disclosures")
            .cloned()
            .unwrap_or_else(|| json!([]));
        return Ok(json!({
            "command": "artifact export",
            "coordinator": coordinator,
            "artifact": args.artifact,
            "to": args.to,
            "receiver_node": args.receiver_node,
            "export_plan": export_plan,
            "local_export": local_export,
            "grant_disclosures": grant_disclosures,
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "artifact export",
        "status": "requires_coordinator",
        "artifact": args.artifact,
        "to": args.to,
        "receiver_node": args.receiver_node,
        "export_plan": {
            "status": "requires_coordinator",
            "explicit_user_action": true,
            "local_bytes_written_by_cli": false,
            "default_durable_store_assumed": false,
            "machine_error": cli_error_summary_for_category(
                "connectivity",
                "artifact export requires a coordinator"
            ),
        },
        "grant_disclosures": [],
    }))
}

fn apply_local_export_summary(export_plan: &mut Value, local_export: &Value) {
    let Some(object) = export_plan.as_object_mut() else {
        return;
    };
    object.insert(
        "local_bytes_written_by_cli".to_owned(),
        local_export
            .get("local_bytes_written_by_cli")
            .cloned()
            .unwrap_or(json!(false)),
    );
    object.insert(
        "local_export_status".to_owned(),
        local_export
            .get("status")
            .cloned()
            .unwrap_or_else(|| json!("unknown")),
    );
    object.insert(
        "content_bytes_available".to_owned(),
        local_export
            .get("content_bytes_available")
            .cloned()
            .unwrap_or(json!(false)),
    );
    if let Some(bytes_written) = local_export.get("bytes_written") {
        object.insert("bytes_written".to_owned(), bytes_written.clone());
        object.insert(
            "writes_require_data_plane_followup".to_owned(),
            json!(false),
        );
    }
}
