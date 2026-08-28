use anyhow::Error;
use clusterflux_core::{ApiError, ApiErrorCode};
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CliFailureCode {
    AuthenticationRequired,
    CoordinatorNotConfigured,
}

impl CliFailureCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "authentication_required",
            Self::CoordinatorNotConfigured => "coordinator_not_configured",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CliFailure {
    pub(crate) code: CliFailureCode,
    message: String,
    pub(crate) coordinator: Option<String>,
}

impl CliFailure {
    pub(crate) fn authentication_required(message: impl Into<String>) -> Self {
        Self {
            code: CliFailureCode::AuthenticationRequired,
            message: message.into(),
            coordinator: None,
        }
    }

    pub(crate) fn coordinator_not_configured(message: impl Into<String>) -> Self {
        Self {
            code: CliFailureCode::CoordinatorNotConfigured,
            message: message.into(),
            coordinator: None,
        }
    }

    pub(crate) fn with_coordinator(mut self, coordinator: impl Into<String>) -> Self {
        self.coordinator = Some(coordinator.into());
        self
    }
}

impl std::fmt::Display for CliFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CliFailure {}

pub(crate) fn cli_error_summary_from_error(error: &Error) -> Value {
    if let Some(error) = error.downcast_ref::<ApiError>() {
        cli_error_summary_for_api_error(error)
    } else if let Some(error) = error.downcast_ref::<CliFailure>() {
        cli_error_summary_for_cli_failure(error)
    } else {
        cli_error_summary(&error.to_string())
    }
}

fn cli_error_summary_for_cli_failure(error: &CliFailure) -> Value {
    let category = match error.code {
        CliFailureCode::AuthenticationRequired => "authentication",
        CliFailureCode::CoordinatorNotConfigured => "connectivity",
    };
    let mut summary = cli_error_summary_for_category(category, &error.message);
    summary
        .as_object_mut()
        .expect("CLI error summary is an object")
        .insert("code".to_owned(), json!(error.code.as_str()));
    summary
}

pub(crate) fn cli_error_summary_for_api_error(error: &ApiError) -> Value {
    let category = match error.code {
        ApiErrorCode::Unauthenticated | ApiErrorCode::SessionExpired => "authentication",
        ApiErrorCode::Forbidden => "authorization",
        ApiErrorCode::AccountSuspended | ApiErrorCode::TaskNotRestartable => "policy",
        ApiErrorCode::QuotaExceeded | ApiErrorCode::ArtifactLimitExceeded => "quota",
        ApiErrorCode::NoCapableNode => "capability",
        ApiErrorCode::NodeOffline
        | ApiErrorCode::TemporaryCapacity
        | ApiErrorCode::ArtifactUnavailable => "connectivity",
        ApiErrorCode::ActiveProcessExists => "active_process",
        ApiErrorCode::ValidationError => "environment",
        ApiErrorCode::DebugEpochPartial => "program",
        ApiErrorCode::NotFound | ApiErrorCode::Conflict | ApiErrorCode::InternalError => "unknown",
    };
    let mut summary = cli_error_summary_for_category(category, &error.message);
    if let Some(object) = summary.as_object_mut() {
        object.insert(
            "code".to_owned(),
            serde_json::to_value(error.code).unwrap_or_else(|_| json!("internal_error")),
        );
        object.insert(
            "api_category".to_owned(),
            serde_json::to_value(error.category).unwrap_or_else(|_| json!("internal")),
        );
        object.insert("request_id".to_owned(), json!(error.request_id));
        object.insert("retryable".to_owned(), json!(error.retryable));
        object.insert("resource".to_owned(), json!(error.resource));
        object.insert("current".to_owned(), json!(error.current));
        object.insert("maximum".to_owned(), json!(error.maximum));
        object.insert(
            "coordinator_next_actions".to_owned(),
            json!(error.next_actions),
        );
    }
    summary
}

pub(crate) fn cli_error_summary(message: &str) -> Value {
    let category = classify_cli_error_message(message);
    cli_error_summary_for_category(category, message)
}

pub(crate) fn cli_error_summary_with_default(
    message: &str,
    default_category: &'static str,
) -> Value {
    let category = classify_cli_error_message(message);
    let category = if category == "unknown" {
        default_category
    } else {
        category
    };
    cli_error_summary_for_category(category, message)
}

pub(crate) fn cli_error_summary_for_category(category: &'static str, message: &str) -> Value {
    let mut summary = json!({
        "category": category,
        "stable_exit_code": cli_error_exit_code(category),
        "process_exit_code_applied": false,
        "retryable_after_user_action": cli_error_retryable_after_user_action(category),
        "message": message,
        "safe_failure": true,
        "next_actions": cli_error_next_actions(category),
    });
    if category == "quota" {
        if let Some(object) = summary.as_object_mut() {
            object.insert(
                "resource_category".to_owned(),
                json!(
                    quota_error_resource_category(message).unwrap_or_else(|| "unknown".to_owned())
                ),
            );
            object.insert("community_tier_language".to_owned(), json!(true));
            object.insert("community_tier_label".to_owned(), json!("community tier"));
            object.insert(
                "sensitive_abuse_heuristics_exposed".to_owned(),
                json!(false),
            );
        }
    }
    summary
}

fn quota_error_resource_category(message: &str) -> Option<String> {
    let lower = message.to_ascii_lowercase();
    for marker in [
        "resource limit exceeded for ",
        "quota unavailable for ",
        "quota exceeded for ",
        "limit exceeded for ",
        "metering limit exceeded for ",
        "quota limit for ",
        "resource category ",
        "resource=",
        "resource:",
    ] {
        if let Some(index) = lower.find(marker) {
            let start = index + marker.len();
            let rest = &message[start..];
            let value: String = rest
                .chars()
                .skip_while(|ch| ch.is_ascii_whitespace())
                .take_while(|ch| {
                    ch.is_ascii_alphanumeric()
                        || *ch == '_'
                        || *ch == '-'
                        || *ch == '.'
                        || *ch == ':'
                })
                .collect();
            let value = value.trim_matches(|ch: char| ch == '.' || ch == ':' || ch == ',');
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn classify_cli_error_message(message: &str) -> &'static str {
    let message = message.to_ascii_lowercase();
    if message.contains("already has active virtual process") || message.contains("active process")
    {
        return "active_process";
    }
    if message_mentions_locality_failure(&message) {
        return "connectivity";
    }
    if message.contains("no capable node")
        || message.contains("missing capability")
        || message.contains("capability")
        || message.contains("placement failed")
        || message.contains("cmd.run")
        || message.contains("node required")
    {
        return "capability";
    }
    if message.contains("quota")
        || message.contains("resource limit")
        || message.contains("limit exceeded")
        || message.contains("metering")
    {
        return "quota";
    }
    if message.contains("policy")
        || message.contains("disallowed")
        || message.contains("not allowed")
        || message.contains("suspended")
        || message.contains("blocked by")
        || message.contains("denied")
    {
        return "policy";
    }
    if message.contains("unauthenticated")
        || message.contains("not authenticated")
        || message.contains("login required")
        || message.contains("browser login required")
        || message.contains("missing session")
        || message.contains("no cli session")
        || message.contains("session credential has expired")
        || message.contains("session credential has been revoked")
        || message.contains("401")
    {
        return "authentication";
    }
    if message.contains("unauthorized")
        || message.contains("not authorized")
        || message.contains("forbidden")
        || message.contains("permission")
        || message.contains("tenant mismatch")
        || message.contains("project mismatch")
    {
        return "authorization";
    }
    if message.contains("failed to connect")
        || message.contains("connection refused")
        || message.contains("closed session")
        || message.contains("timed out")
        || message.contains("timeout")
        || message.contains("name resolution")
        || message.contains("network unreachable")
        || message.contains("dns")
    {
        return "connectivity";
    }
    if message.contains("missing environment")
        || message.contains("environment mismatch")
        || message.contains("incompatible environment")
        || message.contains("containerfile")
        || message.contains("dockerfile")
        || message.contains("envs/")
    {
        return "environment";
    }
    if message.contains("task exited")
        || message.contains("exit status")
        || message.contains("status code")
        || message.contains("stderr")
        || message.contains("panic")
        || message.contains("program error")
        || message.contains("command failed")
    {
        return "program";
    }
    "unknown"
}

pub(crate) fn message_mentions_locality_failure(message: &str) -> bool {
    message.contains("direct connectivity unavailable")
        || message.contains("direct transfer")
        || message.contains("source snapshot unavailable")
        || (message.contains("required artifact")
            && message.contains("unavailable")
            && message.contains("direct connectivity"))
        || message.contains("locality assumption")
}

fn cli_error_exit_code(category: &str) -> i64 {
    match category {
        "authentication" => 20,
        "authorization" => 21,
        "quota" => 22,
        "policy" => 23,
        "capability" => 24,
        "connectivity" => 25,
        "environment" => 26,
        "program" => 27,
        "active_process" => 28,
        _ => 1,
    }
}

fn cli_error_retryable_after_user_action(category: &str) -> bool {
    matches!(
        category,
        "authentication"
            | "authorization"
            | "quota"
            | "policy"
            | "capability"
            | "connectivity"
            | "environment"
            | "program"
            | "active_process"
    )
}

fn cli_error_next_actions(category: &str) -> Vec<&'static str> {
    match category {
        "authentication" => vec!["clusterflux login --browser", "clusterflux auth status"],
        "authorization" => vec![
            "clusterflux auth status",
            "check tenant/project selection",
            "ask an admin to grant access",
        ],
        "quota" => vec![
            "clusterflux quota status",
            "reduce concurrent work or wait for usage to fall",
        ],
        "policy" => vec![
            "clusterflux doctor",
            "check coordinator policy for this action",
        ],
        "capability" => vec![
            "clusterflux node list",
            "attach a node with the required capabilities",
            "check tenant/project on the attached node",
        ],
        "connectivity" => vec![
            "clusterflux doctor",
            "check the coordinator endpoint and network reachability",
        ],
        "environment" => vec![
            "clusterflux inspect",
            "check envs/<name>/Containerfile or envs/<name>/Dockerfile",
        ],
        "program" => vec![
            "clusterflux logs",
            "fix the program or task command and rerun",
        ],
        "active_process" => vec![
            "clusterflux process list",
            "clusterflux process status",
            "clusterflux debug attach",
            "clusterflux process restart --yes",
            "clusterflux process cancel --yes",
            "clusterflux process abort --yes",
            "use another Coordinator Project",
        ],
        _ => vec![
            "clusterflux doctor",
            "rerun with --json for machine-readable details",
        ],
    }
}

#[cfg(test)]
mod tests {
    use clusterflux_core::{ApiError, ApiErrorCategory, ApiErrorCode};

    use super::*;
    use crate::guidance::ensure_report_guidance;

    #[test]
    fn typed_api_code_controls_guidance_independent_of_message_text() {
        let guidance_for = |message: &str| {
            let error = ApiError::new(
                ApiErrorCode::SessionExpired,
                ApiErrorCategory::Authentication,
                message,
                false,
                "request-1",
            );
            let mut report = json!({
                "command": "error",
                "machine_error": cli_error_summary_for_api_error(&error),
            });
            ensure_report_guidance(&mut report).unwrap();
            report["guidance"].clone()
        };

        assert_eq!(
            guidance_for("arbitrary text"),
            guidance_for("totally different text")
        );
    }

    #[test]
    fn typed_local_authentication_failure_does_not_depend_on_message_text() {
        for message in ["no local session", "wording may change freely"] {
            let error = anyhow::Error::new(CliFailure::authentication_required(message));
            let summary = cli_error_summary_from_error(&error);
            assert_eq!(summary["code"], "authentication_required");
            assert_eq!(summary["category"], "authentication");
            assert_eq!(summary["stable_exit_code"], 20);
        }
    }
}
