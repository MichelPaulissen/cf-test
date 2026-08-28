use anyhow::Result;
use serde_json::{json, Value};

use crate::client::list_task_events_if_available_with_session;
use crate::config::StoredCliSession;
use crate::process::hydrate_process_scope;
use crate::process_events::log_entries;
use crate::LogsArgs;

#[cfg(test)]
pub(crate) fn logs_report(args: LogsArgs) -> Result<Value> {
    logs_report_with_session(args, None)
}

pub(crate) fn logs_report_with_session(
    mut args: LogsArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    hydrate_process_scope(&mut args.scope, stored_session);
    let events = list_task_events_if_available_with_session(
        args.scope.coordinator.as_deref(),
        &args.scope,
        args.process.clone(),
        stored_session,
    )?;
    let log_entries = log_entries(events.as_ref(), args.task.as_deref());
    Ok(json!({
        "command": "logs",
        "process": args.process,
        "task": args.task,
        "log_entries": log_entries,
        "logs_are_capped": true,
        "secret_redaction_policy": "configured-redaction-boundary",
        "events": events,
    }))
}
