use std::path::PathBuf;

use anyhow::{Context, Result};
use clusterflux_protocol::{
    AuthenticatedCoordinatorRequest, CoordinatorRequest, CoordinatorResponse,
};
use serde_json::{json, Value};

use crate::client::JsonLineSession;
use crate::config::{read_cli_session, session_config_file, StoredCliSession};
use crate::confirm::confirmation_required_report;
use crate::errors::cli_error_summary;
use crate::AuthLogoutArgs;

pub(crate) fn auth_logout_report(args: AuthLogoutArgs, cwd: PathBuf) -> Result<Value> {
    logout_report(args, cwd, "auth logout")
}

pub(crate) fn logout_report(args: AuthLogoutArgs, cwd: PathBuf, command: &str) -> Result<Value> {
    let session_file = session_config_file(&cwd);
    if !args.yes {
        return Ok(confirmation_required_report(
            command,
            "delete_cli_session",
            json!({
                "session_file": session_file,
                "node_credentials_untouched": true,
            }),
            format!("clusterflux {command} --yes"),
        ));
    }
    let stored_session = read_cli_session(&cwd).ok().flatten();
    let coordinator_revocation = revoke_stored_cli_session_if_possible(stored_session.as_ref());
    let existed = session_file.exists();
    if existed {
        std::fs::remove_file(&session_file)
            .with_context(|| format!("failed to remove {}", session_file.display()))?;
    }
    Ok(json!({
        "command": command,
        "requires_confirmation": !args.yes,
        "removed_cli_session_file": existed,
        "server_session_revocation": coordinator_revocation,
        "node_credentials_untouched": true,
        "session_file": session_file,
    }))
}

fn revoke_stored_cli_session_if_possible(stored_session: Option<&StoredCliSession>) -> Value {
    let Some(session) = stored_session else {
        return json!({
            "attempted": false,
            "revoked": false,
            "reason": "no_parseable_cli_session",
        });
    };
    let Some(session_secret) = session.session_secret.as_deref() else {
        return json!({
            "attempted": false,
            "revoked": false,
            "reason": "no_cli_session_secret",
            "coordinator": session.coordinator,
        });
    };
    // A CLI session credential is authority issued by one coordinator. Never
    // redirect it to a command-line endpoint override.
    let coordinator = session.coordinator.as_str();
    let mut coordinator_session = match JsonLineSession::connect(coordinator) {
        Ok(session) => session,
        Err(error) => {
            let message = error.to_string();
            return json!({
                "attempted": true,
                "revoked": false,
                "reachable": false,
                "coordinator": coordinator,
                "error": message,
                "machine_error": cli_error_summary(&message),
                "next_actions": ["clusterflux login --browser"],
            });
        }
    };
    let response =
        match coordinator_session.request_allow_error(CoordinatorRequest::Authenticated {
            session_secret: session_secret.to_owned(),
            request: AuthenticatedCoordinatorRequest::RevokeCliSession,
        }) {
            Ok(response) => response,
            Err(error) => {
                let message = error.to_string();
                return json!({
                    "attempted": true,
                    "revoked": false,
                    "reachable": false,
                    "coordinator": coordinator,
                    "error": message,
                    "machine_error": cli_error_summary(&message),
                    "coordinator_session_requests": coordinator_session.requests(),
                    "next_actions": ["clusterflux login --browser"],
                });
            }
        };
    if !matches!(&response, CoordinatorResponse::CliSessionRevoked { .. }) {
        let machine_error = match &response {
            CoordinatorResponse::Error { error } => {
                crate::errors::cli_error_summary_for_api_error(error)
            }
            _ => {
                cli_error_summary("coordinator returned an unexpected session-revocation response")
            }
        };
        return json!({
            "attempted": true,
            "revoked": false,
            "reachable": true,
            "coordinator": coordinator,
            "coordinator_response_type": "unexpected",
            "machine_error": machine_error,
            "coordinator_session_requests": coordinator_session.requests(),
            "next_actions": ["clusterflux login --browser"],
        });
    }
    json!({
        "attempted": true,
        "revoked": true,
        "reachable": true,
        "coordinator": coordinator,
        "coordinator_response_type": "cli_session_revoked",
        "coordinator_session_requests": coordinator_session.requests(),
    })
}
