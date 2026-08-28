use anyhow::Result;
use clusterflux_core::Digest;
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};
use serde_json::{json, Value};

use crate::client::{authenticated_or_local_trusted_request, JsonLineSession};
use crate::config::StoredCliSession;
use crate::{confirmation_required_report, KeyAddArgs, KeyListArgs, KeyRevokeArgs};

#[cfg(test)]
pub(crate) fn key_add_report(args: KeyAddArgs) -> Result<Value> {
    key_add_report_with_session(args, None)
}

pub(crate) fn key_add_report_with_session(
    args: KeyAddArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    let coordinator = effective_coordinator(&args.scope.coordinator, stored_session);
    if let Some(coordinator) = &coordinator {
        let tenant = effective_session_value(stored_session, &args.scope.tenant, |session| {
            &session.tenant
        });
        let project = effective_session_value(stored_session, &args.scope.project, |session| {
            &session.project
        });
        let user =
            effective_session_value(stored_session, &args.scope.user, |session| &session.user);
        let agent = args.agent.clone();
        let mut session = JsonLineSession::connect(coordinator)?;
        let response = session.request(authenticated_or_local_trusted_request(
            coordinator,
            stored_session,
            CoordinatorRequest::RegisterAgentPublicKey {
                tenant: tenant.clone(),
                project: project.clone(),
                user: user.clone(),
                agent: agent.clone(),
                public_key: args.public_key.clone(),
            },
        )?)?;
        let record = match &response {
            CoordinatorResponse::AgentPublicKey { record, .. } => record,
            _ => anyhow::bail!("coordinator returned an unexpected agent-key response"),
        };
        return Ok(json!({
            "command": "key add",
            "coordinator": coordinator,
            "tenant": tenant,
            "project": project,
            "user": user,
            "agent": agent,
            "public_key_fingerprint": record.public_key_fingerprint,
            "credential_scope": {
                "tenant": tenant,
                "project": project,
                "actions": record.scopes,
                "human_account_creation_privilege": record.human_account_creation_privilege,
            },
            "browser_interaction_required_each_run": record.browser_interaction_required_each_run,
            "attribution": {
                "registered_by_user": user,
                "agent": agent,
                "credential_kind": "public_key",
            },
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "key add",
        "status": "planned_without_coordinator",
        "agent": args.agent,
        "public_key_fingerprint": Digest::sha256(args.public_key),
        "browser_interaction_required_each_run": false,
    }))
}

#[cfg(test)]
pub(crate) fn key_list_report(args: KeyListArgs) -> Result<Value> {
    key_list_report_with_session(args, None)
}

pub(crate) fn key_list_report_with_session(
    args: KeyListArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    let coordinator = effective_coordinator(&args.scope.coordinator, stored_session);
    if let Some(coordinator) = &coordinator {
        let tenant = effective_session_value(stored_session, &args.scope.tenant, |session| {
            &session.tenant
        });
        let project = effective_session_value(stored_session, &args.scope.project, |session| {
            &session.project
        });
        let user =
            effective_session_value(stored_session, &args.scope.user, |session| &session.user);
        let mut session = JsonLineSession::connect(coordinator)?;
        let response = session.request(authenticated_or_local_trusted_request(
            coordinator,
            stored_session,
            CoordinatorRequest::ListAgentPublicKeys {
                tenant: tenant.clone(),
                project: project.clone(),
                user: user.clone(),
            },
        )?)?;
        let records = match &response {
            CoordinatorResponse::AgentPublicKeys { records, .. } => records,
            _ => anyhow::bail!("coordinator returned an unexpected agent-key-list response"),
        };
        return Ok(json!({
            "command": "key list",
            "coordinator": coordinator,
            "tenant": tenant,
            "project": project,
            "user": user,
            "records": records,
            "credential_scope": {
                "tenant": tenant,
                "project": project,
                "listed_for_user": user,
                "human_account_creation_privilege": false,
            },
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "key list",
        "status": "requires_coordinator",
        "records": [],
    }))
}

#[cfg(test)]
pub(crate) fn key_revoke_report(args: KeyRevokeArgs) -> Result<Value> {
    key_revoke_report_with_session(args, None)
}

pub(crate) fn key_revoke_report_with_session(
    args: KeyRevokeArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    if !args.yes {
        return Ok(confirmation_required_report(
            "key revoke",
            "revoke_agent_public_key",
            json!({
                "coordinator": args.scope.coordinator,
                "tenant": args.scope.tenant,
                "project": args.scope.project,
                "user": args.scope.user,
                "agent": args.agent,
            }),
            format!("clusterflux key revoke --agent {} --yes", args.agent),
        ));
    }
    let coordinator = effective_coordinator(&args.scope.coordinator, stored_session);
    if let Some(coordinator) = &coordinator {
        let tenant = effective_session_value(stored_session, &args.scope.tenant, |session| {
            &session.tenant
        });
        let project = effective_session_value(stored_session, &args.scope.project, |session| {
            &session.project
        });
        let user =
            effective_session_value(stored_session, &args.scope.user, |session| &session.user);
        let agent = args.agent.clone();
        let mut session = JsonLineSession::connect(coordinator)?;
        let response = session.request(authenticated_or_local_trusted_request(
            coordinator,
            stored_session,
            CoordinatorRequest::RevokeAgentPublicKey {
                tenant: tenant.clone(),
                project: project.clone(),
                user: user.clone(),
                agent: agent.clone(),
            },
        )?)?;
        let revoked = match &response {
            CoordinatorResponse::AgentPublicKey { record, .. } => record.revoked,
            _ => anyhow::bail!("coordinator returned an unexpected agent-key-revoke response"),
        };
        return Ok(json!({
            "command": "key revoke",
            "coordinator": coordinator,
            "requires_confirmation": !args.yes,
            "tenant": tenant,
            "project": project,
            "user": user,
            "agent": agent,
            "revoked": revoked,
            "credential_scope": {
                "tenant": tenant,
                "project": project,
                "revoked_for_user": user,
                "human_account_creation_privilege": false,
            },
            "attribution": {
                "revoked_by_user": user,
                "agent": agent,
                "credential_kind": "public_key",
            },
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "key revoke",
        "status": "requires_coordinator",
        "requires_confirmation": !args.yes,
        "agent": args.agent,
    }))
}

fn effective_coordinator(
    requested: &Option<String>,
    stored_session: Option<&StoredCliSession>,
) -> Option<String> {
    requested.clone().or_else(|| {
        stored_session
            .filter(|session| session.session_secret.is_some())
            .map(|session| session.coordinator.clone())
    })
}

fn effective_session_value(
    stored_session: Option<&StoredCliSession>,
    requested: &str,
    value: impl FnOnce(&StoredCliSession) -> &String,
) -> String {
    stored_session
        .filter(|session| session.session_secret.is_some())
        .map(value)
        .cloned()
        .unwrap_or_else(|| requested.to_owned())
}
