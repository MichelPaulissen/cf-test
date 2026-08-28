use serde_json::{json, Value};

use crate::errors::cli_error_summary_for_category;

pub(crate) fn confirmation_required_report(
    command: &str,
    operation: &str,
    target: Value,
    confirm_command: String,
) -> Value {
    let message = format!("{command} requires --yes before {operation}");
    let next_actions = json!([
        confirm_command,
        "review the command target before confirming",
        "rerun with --json to inspect the safe failure"
    ]);
    let mut machine_error = cli_error_summary_for_category("policy", &message);
    if let Some(object) = machine_error.as_object_mut() {
        object.insert("confirmation_required".to_owned(), json!(true));
        object.insert("next_actions".to_owned(), next_actions.clone());
    }
    json!({
        "command": command,
        "status": "confirmation_required",
        "operation": operation,
        "target": target,
        "requires_confirmation": true,
        "confirmation_required": true,
        "explicit_user_action_required": true,
        "coordinator_request_sent": false,
        "safe_failure": true,
        "next_actions": next_actions,
        "machine_error": machine_error,
    })
}
