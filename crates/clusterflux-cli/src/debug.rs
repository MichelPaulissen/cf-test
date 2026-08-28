use std::process::Command;

use anyhow::{Context, Result};
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};
use serde_json::{json, Value};

use crate::client::{
    authenticated_or_local_trusted_request, stored_session_for_coordinator, JsonLineSession,
};
use crate::config::StoredCliSession;
use crate::tools::dap_binary_path;
use crate::{DapArgs, DebugAttachArgs};

pub(crate) fn dap_plan(args: DapArgs) -> Result<Value> {
    Ok(json!({
        "command": "dap",
        "adapter": dap_binary_path()?.display().to_string(),
        "args": args.args,
        "external_website_required": false,
    }))
}

pub(crate) fn exec_dap(args: DapArgs) -> Result<()> {
    let status = Command::new(dap_binary_path()?)
        .args(args.args)
        .status()
        .context("failed to launch clusterflux-debug-dap")?;
    if !status.success() {
        anyhow::bail!("clusterflux-debug-dap exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn debug_attach_report_with_dap(args: DebugAttachArgs, dap: String) -> Result<Value> {
    debug_attach_report_with_dap_and_session(args, dap, None)
}

pub(crate) fn debug_attach_report_with_dap_and_session(
    mut args: DebugAttachArgs,
    dap: String,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    if args.scope.coordinator.is_none() {
        args.scope.coordinator = stored_session
            .filter(|session| session.session_secret.is_some())
            .map(|session| session.coordinator.clone());
    }
    if let Some(bound_session) = args
        .scope
        .coordinator
        .as_deref()
        .and_then(|coordinator| stored_session_for_coordinator(coordinator, stored_session))
    {
        args.scope.tenant = bound_session.tenant.clone();
        args.scope.project = bound_session.project.clone();
        args.scope.user = bound_session.user.clone();
    }
    if let Some(coordinator) = &args.scope.coordinator {
        let tenant = args.scope.tenant.clone();
        let project = args.scope.project.clone();
        let user = args.scope.user.clone();
        let process = args.process.clone();
        let mut session = JsonLineSession::connect(coordinator)?;
        let response = session.request(authenticated_or_local_trusted_request(
            coordinator,
            stored_session,
            CoordinatorRequest::DebugAttach {
                tenant: tenant.clone(),
                project: project.clone(),
                actor_user: user.clone(),
                process: process.clone(),
            },
        )?)?;
        let (authorization, audit_event, charged, used) = match response {
            CoordinatorResponse::DebugAttach {
                authorization,
                audit_event,
                charged_debug_read_bytes,
                used_debug_read_bytes,
                ..
            } => (
                authorization,
                audit_event,
                charged_debug_read_bytes,
                used_debug_read_bytes,
            ),
            _ => anyhow::bail!("coordinator returned an unexpected debug-attach response"),
        };
        return Ok(json!({
            "command": "debug attach",
            "process": process,
            "coordinator": coordinator,
            "tenant": tenant,
            "project": project,
            "user": user,
            "dap": dap,
            "authorized": authorization.allowed,
            "authorization": authorization,
            "audit_event": audit_event,
            "charged_debug_read_bytes": charged,
            "used_debug_read_bytes": used,
            "debug_reads_quota_limited": true,
            "external_website_required": false,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "debug attach",
        "process": args.process,
        "coordinator": args.scope.coordinator,
        "tenant": args.scope.tenant,
        "project": args.scope.project,
        "dap": dap,
        "authorized": "unknown_without_coordinator",
        "debug_reads_quota_limited": "unknown_without_coordinator",
        "external_website_required": false,
    }))
}
