use std::path::PathBuf;

use anyhow::Result;
use clusterflux_core::admin_request_proof;
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};
use serde_json::{json, Value};

use crate::client::JsonLineSession;
use crate::project::project_init_report;
use crate::tools::{command_nonce, unix_timestamp_seconds};
use crate::{
    confirmation_required_report, AdminBootstrapArgs, AdminStatusArgs, AdminSuspendTenantArgs,
    ProjectInitArgs,
};

pub(crate) fn admin_status_report(args: AdminStatusArgs) -> Result<Value> {
    if let Some(coordinator) = &args.scope.coordinator {
        let tenant = args.scope.tenant.clone();
        let user = args.scope.user.clone();
        let admin_token = admin_token_for_request(args.admin_token.as_deref())?;
        let admin_nonce = command_nonce("admin-status");
        let issued_at_epoch_seconds = unix_timestamp_seconds();
        let admin_proof = admin_request_proof(
            &admin_token,
            "admin_status",
            &tenant,
            &user,
            &tenant,
            &admin_nonce,
            issued_at_epoch_seconds,
        );
        let mut session = JsonLineSession::connect(coordinator)?;
        let response = session.request(CoordinatorRequest::AdminStatus {
            tenant: tenant.clone(),
            actor_user: user.clone(),
            admin_proof,
            admin_nonce,
            issued_at_epoch_seconds,
        })?;
        let suspended = match &response {
            CoordinatorResponse::AdminStatus { suspended, .. } => *suspended,
            _ => anyhow::bail!("coordinator returned an unexpected admin-status response"),
        };
        return Ok(json!({
            "command": "admin status",
            "coordinator": coordinator,
            "tenant": tenant,
            "user": user,
            "suspended": suspended,
            "response": serde_json::to_value(response)?,
            "safe_default": "read_only",
            "external_website_required": false,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "admin status",
        "mode": "self_hosted_local",
        "safe_default": "read_only",
        "external_website_required": false,
    }))
}

pub(crate) fn admin_bootstrap_report(args: AdminBootstrapArgs, cwd: PathBuf) -> Result<Value> {
    let scope = args.scope.clone();
    let new_project = args.scope.project.clone();
    let project_init = project_init_report(
        ProjectInitArgs {
            scope: args.scope,
            new_project,
            name: args.name,
            yes: args.yes,
        },
        cwd,
    )?;
    let coordinator = scope
        .coordinator
        .clone()
        .unwrap_or_else(|| "<local-coordinator>".to_owned());
    let tenant = scope.tenant.clone();
    let project = scope.project.clone();
    let user = scope.user.clone();
    Ok(json!({
        "command": "admin bootstrap",
        "mode": if scope.coordinator.is_some() { "public_coordinator_api" } else { "self_hosted_local" },
        "tenant": tenant.clone(),
        "project": project.clone(),
        "user": user,
        "coordinator": scope.coordinator,
        "external_website_required": false,
        "self_hosted_cli_only": true,
        "project_config_written": project_init
            .get("project_config_written")
            .cloned()
            .unwrap_or(json!(false)),
        "project_init": project_init,
        "admin_surfaces": {
            "coordinator": "clusterflux-coordinator",
            "project": "clusterflux project init/status/list/select",
            "node": "clusterflux node enroll/list/status/revoke",
            "process": "clusterflux run/process status/process restart/process cancel",
            "logs": "clusterflux logs",
            "artifacts": "clusterflux artifact list/download/export",
            "quota": "clusterflux quota status",
            "policy": "clusterflux admin status/suspend-tenant",
        },
        "bootstrap_sequence": [
            {
                "step": "start_self_hosted_coordinator",
                "command": "clusterflux-coordinator --listen 127.0.0.1:0",
                "external_website_required": false,
            },
            {
                "step": "create_or_link_project",
                "command": "clusterflux project init --yes",
                "completed": true,
                "external_website_required": false,
            },
            {
                "step": "create_node_enrollment_grant",
                "command": format!(
                    "clusterflux node enroll --coordinator {coordinator} --tenant {} --project-id {}",
                    tenant, project
                ),
                "external_website_required": false,
            },
            {
                "step": "attach_worker_node",
                "command": format!(
                    "clusterflux node attach --coordinator {coordinator} --tenant {} --project-id {} --worker",
                    tenant, project
                ),
                "external_website_required": false,
            },
            {
                "step": "run_process",
                "command": format!(
                    "clusterflux run --coordinator {coordinator} --tenant {} --project-id {}",
                    tenant, project
                ),
                "external_website_required": false,
            },
            {
                "step": "inspect_status_logs_artifacts",
                "commands": [
                    "clusterflux process status",
                    "clusterflux task list",
                    "clusterflux logs",
                    "clusterflux artifact list",
                    "clusterflux quota status",
                ],
                "external_website_required": false,
            },
            {
                "step": "revoke_access",
                "command": "clusterflux admin revoke-node --node <node-id> --yes",
                "external_website_required": false,
            }
        ],
    }))
}

pub(crate) fn admin_suspend_tenant_report(args: AdminSuspendTenantArgs) -> Result<Value> {
    let tenant = args
        .target_tenant
        .unwrap_or_else(|| args.scope.tenant.clone());
    if !args.yes {
        return Ok(confirmation_required_report(
            "admin suspend-tenant",
            "suspend_tenant",
            json!({
                "coordinator": args.scope.coordinator,
                "actor_tenant": args.scope.tenant,
                "actor_user": args.scope.user,
                "target_tenant": tenant,
            }),
            "clusterflux admin suspend-tenant --yes".to_owned(),
        ));
    }
    if let Some(coordinator) = &args.scope.coordinator {
        let actor_tenant = args.scope.tenant.clone();
        let actor_user = args.scope.user.clone();
        let admin_token = admin_token_for_request(args.admin_token.as_deref())?;
        let admin_nonce = command_nonce("admin-suspend-tenant");
        let issued_at_epoch_seconds = unix_timestamp_seconds();
        let admin_proof = admin_request_proof(
            &admin_token,
            "suspend_tenant",
            &actor_tenant,
            &actor_user,
            &tenant,
            &admin_nonce,
            issued_at_epoch_seconds,
        );
        let mut session = JsonLineSession::connect(coordinator)?;
        let response = session.request(CoordinatorRequest::SuspendTenant {
            tenant: actor_tenant.clone(),
            actor_user: actor_user.clone(),
            target_tenant: tenant.clone(),
            admin_proof,
            admin_nonce,
            issued_at_epoch_seconds,
        })?;
        let suspended = matches!(&response, CoordinatorResponse::TenantSuspended { .. });
        if !suspended {
            anyhow::bail!("coordinator returned an unexpected tenant-suspension response");
        }
        return Ok(json!({
            "command": "admin suspend-tenant",
            "coordinator": coordinator,
            "requires_confirmation": !args.yes,
            "tenant": tenant,
            "actor_tenant": actor_tenant,
            "actor_user": actor_user,
            "suspended": suspended,
            "external_website_required": false,
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "admin suspend-tenant",
        "status": "requires_coordinator",
        "requires_confirmation": !args.yes,
        "tenant": tenant,
        "external_website_required": false,
    }))
}

fn admin_token_for_request(explicit: Option<&str>) -> Result<String> {
    explicit
        .map(str::to_owned)
        .or_else(|| std::env::var("CLUSTERFLUX_ADMIN_TOKEN").ok())
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "admin command requires --admin-token or CLUSTERFLUX_ADMIN_TOKEN for coordinator requests"
            )
        })
}
