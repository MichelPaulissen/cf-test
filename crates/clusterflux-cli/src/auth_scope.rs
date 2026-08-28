use std::path::Path;

use anyhow::Result;
use serde_json::{json, Value};

use crate::client::control_endpoint_identity;
use crate::config::{
    effective_scope_value, read_project_config, StoredCliSession,
    DEFAULT_HOSTED_COORDINATOR_ENDPOINT,
};
use crate::errors::cli_error_summary_for_category;
use crate::LoginArgs;

pub(crate) fn login_args_for_project(mut args: LoginArgs, cwd: &Path) -> Result<LoginArgs> {
    let Some(config) = read_project_config(cwd)? else {
        return Ok(args);
    };
    args.project = effective_scope_value(&args.project, Some(&config.project), "project");
    if args.coordinator == DEFAULT_HOSTED_COORDINATOR_ENDPOINT {
        if let Some(coordinator) = config.coordinator {
            args.coordinator = coordinator;
        }
    }
    Ok(args)
}

pub(crate) fn session_scope_mismatch(
    session: Option<&StoredCliSession>,
    active_coordinator: &str,
    tenant: &str,
    project: &str,
    user: &str,
) -> Option<Vec<&'static str>> {
    session.and_then(|session| {
        let mut fields = Vec::new();
        if control_endpoint_identity(&session.coordinator).ok()
            != control_endpoint_identity(active_coordinator).ok()
        {
            fields.push("coordinator");
        }
        if session.tenant != tenant {
            fields.push("tenant");
        }
        if session.project != project {
            fields.push("project");
        }
        if session.user != user {
            fields.push("user");
        }
        (!fields.is_empty()).then_some(fields)
    })
}

pub(crate) fn session_scope_mismatch_status(fields: &[&str]) -> Value {
    json!({
        "checked": false,
        "reason": "stored CLI session does not match the current project",
        "mismatched_fields": fields,
        "authenticated_for_current_project": false,
        "account_status": "unknown",
        "suspension_known": false,
        "account_state_known": false,
        "sensitive_moderation_details_exposed": false,
        "signup_failure_details_exposed": false,
        "next_actions": ["clusterflux login --browser"],
    })
}

pub(crate) fn non_interactive_auth_machine_error(
    message: &str,
    next_actions: Vec<&'static str>,
) -> Value {
    let mut machine_error = cli_error_summary_for_category("authentication", message);
    if let Some(object) = machine_error.as_object_mut() {
        object.insert("next_actions".to_owned(), json!(next_actions));
        object.insert("browser_opened".to_owned(), json!(false));
    }
    machine_error
}
