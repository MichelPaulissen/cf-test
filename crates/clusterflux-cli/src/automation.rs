use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clusterflux_protocol::{
    AuthenticatedCoordinatorRequest, CoordinatorRequest, CoordinatorResponse, TaskAttemptState,
    TaskTerminalState,
};
use serde_json::{json, Value};

use crate::client::JsonLineSession;
use crate::config::StoredCliSession;
use crate::{
    RunCancelArgs, RunDiagnoseArgs, RunListArgs, RunRetryArgs, RunShowArgs, RunTriggerArgs,
    SecretListArgs, SecretRevokeArgs, SecretSetArgs, WebhookDeliveriesArgs,
};

pub(crate) fn run_list_report(args: RunListArgs, cwd: &Path) -> Result<Value> {
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    match session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::ListAutomatedRuns {
            cursor: None,
            limit: 64,
        },
    })? {
        CoordinatorResponse::AutomatedRuns { runs, actor, .. } => Ok(json!({
            "command": "runs list",
            "coordinator": coordinator,
            "actor": actor,
            "runs": runs,
            "coordinator_session_requests": session.requests(),
        })),
        response => anyhow::bail!("unexpected runs list response: {response:?}"),
    }
}

pub(crate) fn run_show_report(args: RunShowArgs, cwd: &Path) -> Result<Value> {
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    match session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::GetAutomatedRun {
            run: args.run.to_string(),
        },
    })? {
        CoordinatorResponse::AutomatedRun { run, actor } => Ok(json!({
            "command": "runs show",
            "coordinator": coordinator,
            "actor": actor,
            "run": run,
            "coordinator_session_requests": session.requests(),
        })),
        response => anyhow::bail!("unexpected runs show response: {response:?}"),
    }
}

pub(crate) fn run_cancel_report(args: RunCancelArgs, cwd: &Path) -> Result<Value> {
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    match session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::CancelAutomatedRun {
            run: args.run.to_string(),
        },
    })? {
        CoordinatorResponse::AutomatedRun { run, actor } => Ok(json!({
            "command": "runs cancel",
            "coordinator": coordinator,
            "actor": actor,
            "run": run,
            "coordinator_session_requests": session.requests(),
        })),
        response => anyhow::bail!("unexpected runs cancel response: {response:?}"),
    }
}

pub(crate) fn run_retry_report(args: RunRetryArgs, cwd: &Path) -> Result<Value> {
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    let original_run = args.run.to_string();
    let response = session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::RetryAutomatedRun {
            run: original_run.clone(),
        },
    })?;
    let CoordinatorResponse::AutomatedRun { run, actor } = response else {
        anyhow::bail!("unexpected runs retry response: {response:?}");
    };
    let run_id = run.run_id.to_string();
    let mut report = json!({
        "command": "runs retry",
        "coordinator": coordinator,
        "actor": actor,
        "original_run": original_run,
        "run": run,
        "coordinator_session_requests": session.requests(),
    });
    attach_run_wait_guidance(&mut report, &coordinator, &run_id, "terminal", "30m")?;
    Ok(report)
}

pub(crate) fn run_trigger_report(args: RunTriggerArgs, cwd: &Path) -> Result<Value> {
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    let response = session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::TriggerAutomatedRun {
            repository: args.repository.to_string(),
            git_ref: args.git_ref,
            commit: args.commit,
        },
    })?;
    let CoordinatorResponse::AutomatedRun { run, actor } = response else {
        anyhow::bail!("unexpected runs trigger response: {response:?}");
    };
    let run_id = run.run_id.to_string();
    let mut report = json!({
        "command": "runs trigger",
        "coordinator": coordinator,
        "actor": actor,
        "run": run,
        "coordinator_session_requests": session.requests(),
    });
    attach_run_wait_guidance(&mut report, &coordinator, &run_id, "terminal", "30m")?;
    Ok(report)
}

pub(crate) fn run_diagnose_report(args: RunDiagnoseArgs, cwd: &Path) -> Result<Value> {
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    let response = session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret.clone(),
        request: AuthenticatedCoordinatorRequest::GetAutomatedRun {
            run: args.run.to_string(),
        },
    })?;
    let CoordinatorResponse::AutomatedRun { run, actor } = response else {
        anyhow::bail!("unexpected runs diagnose response: {response:?}");
    };

    let (failed_task, log_tail) = if let Some(process) = &run.process_id {
        let snapshots = match session.request_typed(CoordinatorRequest::Authenticated {
            session_secret: secret.clone(),
            request: AuthenticatedCoordinatorRequest::ListTaskSnapshots {
                process: process.to_string(),
            },
        })? {
            CoordinatorResponse::TaskSnapshots { snapshots } => snapshots,
            response => anyhow::bail!("unexpected task-snapshot response: {response:?}"),
        };
        let events = match session.request_typed(CoordinatorRequest::Authenticated {
            session_secret: secret,
            request: AuthenticatedCoordinatorRequest::ListTaskEvents {
                process: Some(process.to_string()),
            },
        })? {
            CoordinatorResponse::TaskEvents { events } => events,
            response => anyhow::bail!("unexpected task-event response: {response:?}"),
        };
        let failed = snapshots
            .iter()
            .filter(|snapshot| {
                matches!(
                    snapshot.state,
                    TaskAttemptState::Failed | TaskAttemptState::FailedAwaitingAction
                )
            })
            .max_by_key(|snapshot| (snapshot.current, snapshot.attempt_number))
            .cloned();
        let event = failed.as_ref().and_then(|snapshot| {
            events.iter().rev().find(|event| {
                event.task == snapshot.task
                    && event.attempt_id.as_deref() == Some(snapshot.attempt_id.as_str())
                    && event.terminal_state == TaskTerminalState::Failed
            })
        });
        let tail = event.map(|event| {
            json!({
                "task": event.task,
                "attempt_id": event.attempt_id,
                "stdout": event.stdout_tail,
                "stderr": event.stderr_tail,
                "stdout_bytes": event.stdout_bytes,
                "stderr_bytes": event.stderr_bytes,
                "stdout_truncated": event.stdout_truncated,
                "stderr_truncated": event.stderr_truncated,
            })
        });
        (serde_json::to_value(failed)?, tail)
    } else {
        (Value::Null, None)
    };
    let run_id = run.run_id.to_string();
    let state = run.state.clone();
    let mut report = json!({
        "command": "runs diagnose",
        "coordinator": coordinator,
        "actor": actor,
        "run": run,
        "run_failure": {
            "code": run.failure_code,
            "message": run.failure_message,
        },
        "failed_task": failed_task,
        "log_tail": log_tail,
        "diagnostic_output_bounded": true,
        "coordinator_session_requests": session.requests(),
    });
    use crate::guidance::{attach_guidance, GuidanceKind, GuidedCommand, OperationGuidance};
    let guidance = if !state.is_terminal() {
        run_wait_guidance(&coordinator, &run_id, "terminal", "30m")?
    } else if matches!(
        state,
        clusterflux_core::AutomatedRunState::Failed
            | clusterflux_core::AutomatedRunState::Cancelled
    ) {
        OperationGuidance::no_safe_action(
            "diagnosis is complete; retry only after addressing the reported cause",
        )
        .alternative(GuidedCommand::new(
            GuidanceKind::Retry,
            [
                "clusterflux",
                "runs",
                "retry",
                run_id.as_str(),
                "--coordinator",
                coordinator.as_str(),
            ],
            true,
            false,
        ))
        .build()?
    } else {
        OperationGuidance::no_safe_action("run completed successfully; no follow-up is required")
            .build()?
    };
    attach_guidance(&mut report, guidance)?;
    Ok(report)
}

pub(crate) fn webhook_deliveries_report(args: WebhookDeliveriesArgs, cwd: &Path) -> Result<Value> {
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    let response = session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::ListWebhookDeliveries {
            cursor: None,
            limit: 100,
        },
    })?;
    let CoordinatorResponse::WebhookDeliveries {
        deliveries,
        next_cursor,
        actor,
    } = response
    else {
        anyhow::bail!("unexpected webhook deliveries response: {response:?}");
    };
    let mut report = json!({
        "command": "webhook deliveries",
        "coordinator": coordinator,
        "actor": actor,
        "deliveries": deliveries,
        "next_cursor": next_cursor,
        "bounded": true,
        "coordinator_session_requests": session.requests(),
    });
    use crate::guidance::{attach_guidance, OperationGuidance};
    attach_guidance(
        &mut report,
        OperationGuidance::no_safe_action(
            "delivery history is informational; no follow-up is required",
        )
        .build()?,
    )?;
    Ok(report)
}

fn attach_run_wait_guidance(
    report: &mut Value,
    coordinator: &str,
    run: &str,
    condition: &str,
    timeout: &str,
) -> Result<()> {
    crate::guidance::attach_guidance(
        report,
        run_wait_guidance(coordinator, run, condition, timeout)?,
    )?;
    Ok(())
}

fn run_wait_guidance(
    coordinator: &str,
    run: &str,
    condition: &str,
    timeout: &str,
) -> Result<crate::guidance::OperationGuidance> {
    use crate::guidance::{GuidanceKind, GuidedCommand, OperationGuidance};
    Ok(OperationGuidance::recommended(GuidedCommand::new(
        GuidanceKind::Wait,
        [
            "clusterflux",
            "wait",
            "run",
            "--run",
            run,
            "--for",
            condition,
            "--timeout",
            timeout,
            "--coordinator",
            coordinator,
        ],
        false,
        false,
    ))
    .build()?)
}

pub(crate) fn secret_set_report(args: SecretSetArgs, cwd: &Path) -> Result<Value> {
    if !args.stdin {
        anyhow::bail!("secret set requires --stdin; values are never accepted as arguments");
    }
    let mut value = Vec::new();
    std::io::stdin()
        .take((16 * 1024 + 1) as u64)
        .read_to_end(&mut value)
        .context("read project secret from stdin")?;
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        value.pop();
    }
    if value.len() < 16 || value.len() > 16 * 1024 {
        anyhow::bail!("project secret must contain 16 through 16384 bytes");
    }
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    match session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::SetProjectSecret {
            name: args.name,
            value_base64: BASE64_STANDARD.encode(value),
        },
    })? {
        CoordinatorResponse::ProjectSecretSet { secret, actor } => Ok(json!({
            "command": "secret set",
            "coordinator": coordinator,
            "actor": actor,
            "secret": secret,
            "coordinator_session_requests": session.requests(),
        })),
        response => anyhow::bail!("unexpected secret set response: {response:?}"),
    }
}

pub(crate) fn secret_list_report(args: SecretListArgs, cwd: &Path) -> Result<Value> {
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    match session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::ListProjectSecrets,
    })? {
        CoordinatorResponse::ProjectSecrets { secrets, actor } => Ok(json!({
            "command": "secret list",
            "coordinator": coordinator,
            "actor": actor,
            "secrets": secrets,
            "coordinator_session_requests": session.requests(),
        })),
        response => anyhow::bail!("unexpected secret list response: {response:?}"),
    }
}

pub(crate) fn secret_revoke_report(args: SecretRevokeArgs, cwd: &Path) -> Result<Value> {
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    match session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::RevokeProjectSecret { name: args.name },
    })? {
        CoordinatorResponse::ProjectSecretRevoked { secret, actor } => Ok(json!({
            "command": "secret revoke",
            "coordinator": coordinator,
            "actor": actor,
            "secret": secret,
            "coordinator_session_requests": session.requests(),
        })),
        response => anyhow::bail!("unexpected secret revoke response: {response:?}"),
    }
}

fn session_authority(
    configured: &Option<String>,
    stored: Option<&StoredCliSession>,
) -> Result<(String, String)> {
    let coordinator = configured
        .clone()
        .or_else(|| stored.map(|session| session.coordinator.clone()))
        .ok_or_else(|| {
            crate::errors::CliFailure::coordinator_not_configured(
                "no coordinator is configured for the current project",
            )
        })?;
    let session = crate::client::stored_session_for_coordinator(&coordinator, stored)
        .and_then(|session| session.session_secret.clone())
        .ok_or_else(|| {
            crate::errors::CliFailure::authentication_required(format!(
                "no authenticated session matches {coordinator}"
            ))
            .with_coordinator(coordinator.clone())
        })?;
    Ok((coordinator, session))
}
