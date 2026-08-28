use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    Unauthenticated,
    SessionExpired,
    AccountSuspended,
    Forbidden,
    ValidationError,
    NotFound,
    Conflict,
    ActiveProcessExists,
    NodeOffline,
    NoCapableNode,
    TaskNotRestartable,
    ArtifactUnavailable,
    ArtifactLimitExceeded,
    QuotaExceeded,
    TemporaryCapacity,
    DebugEpochPartial,
    InternalError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCategory {
    Authentication,
    Authorization,
    Validation,
    State,
    Availability,
    Resource,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub code: ApiErrorCode,
    pub category: ApiErrorCategory,
    pub message: String,
    pub retryable: bool,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next_actions: Vec<String>,
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} (code {:?}, request {})",
            self.message, self.code, self.request_id
        )
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    pub fn new(
        code: ApiErrorCode,
        category: ApiErrorCategory,
        message: impl Into<String>,
        retryable: bool,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            code,
            category,
            message: message.into(),
            retryable,
            request_id: request_id.into(),
            resource: None,
            current: None,
            maximum: None,
            next_actions: Vec::new(),
        }
    }

    pub fn with_quota_details(
        mut self,
        resource: impl Into<String>,
        current: u64,
        maximum: u64,
        next_actions: impl IntoIterator<Item = String>,
    ) -> Self {
        self.resource = Some(resource.into());
        self.current = Some(current);
        self.maximum = Some(maximum);
        self.next_actions = next_actions.into_iter().collect();
        self
    }

    pub fn from_message(request_id: impl Into<String>, message: impl Into<String>) -> Self {
        let request_id = request_id.into();
        let message = message.into();
        let normalized = message.to_ascii_lowercase();
        let (code, category, retryable) = if normalized.contains("session credential has expired")
            || normalized.contains("session expired")
        {
            (
                ApiErrorCode::SessionExpired,
                ApiErrorCategory::Authentication,
                false,
            )
        } else if normalized.contains("tenant is suspended")
            || normalized.contains("account is suspended")
            || normalized.contains("suspended by hosted")
        {
            (
                ApiErrorCode::AccountSuspended,
                ApiErrorCategory::Authorization,
                false,
            )
        } else if normalized.contains("session credential")
            || normalized.contains("no authenticated")
            || normalized.contains("not authenticated")
            || normalized.contains("credential is not")
        {
            (
                ApiErrorCode::Unauthenticated,
                ApiErrorCategory::Authentication,
                false,
            )
        } else if normalized.contains("project already has active virtual process") {
            (
                ApiErrorCode::ActiveProcessExists,
                ApiErrorCategory::State,
                false,
            )
        } else if normalized.contains("no capable node")
            || normalized.contains("node has no capability report")
        {
            (
                ApiErrorCode::NoCapableNode,
                ApiErrorCategory::Availability,
                true,
            )
        } else if normalized.contains("node offline")
            || normalized.contains("node is not live")
            || normalized.contains("source node is not connected")
            || normalized.contains("direct connectivity unavailable")
        {
            (
                ApiErrorCode::NodeOffline,
                ApiErrorCategory::Availability,
                true,
            )
        } else if normalized.contains("restart")
            && (normalized.contains("not restartable")
                || normalized.contains("requires whole")
                || normalized.contains("clean boundary"))
        {
            (
                ApiErrorCode::TaskNotRestartable,
                ApiErrorCategory::State,
                false,
            )
        } else if normalized.contains("artifact")
            && (normalized.contains("exceeds download limit")
                || normalized.contains("download session limit")
                || normalized.contains("artifact limit"))
        {
            (
                ApiErrorCode::ArtifactLimitExceeded,
                ApiErrorCategory::Resource,
                false,
            )
        } else if normalized.contains("artifact")
            && (normalized.contains("does not exist")
                || normalized.contains("not found")
                || normalized.contains("unknown artifact"))
        {
            (ApiErrorCode::NotFound, ApiErrorCategory::State, false)
        } else if normalized.contains("artifact")
            && (normalized.contains("unavailable") || normalized.contains("retention"))
        {
            (
                ApiErrorCode::ArtifactUnavailable,
                ApiErrorCategory::Availability,
                true,
            )
        } else if normalized.contains("resource limit")
            || normalized.contains("quota")
            || normalized.contains("limit exceeded")
        {
            (
                ApiErrorCode::QuotaExceeded,
                ApiErrorCategory::Resource,
                true,
            )
        } else if normalized.contains("capacity")
            || normalized.contains("temporarily full")
            || normalized.contains("replay window is full")
        {
            (
                ApiErrorCode::TemporaryCapacity,
                ApiErrorCategory::Availability,
                true,
            )
        } else if normalized.contains("partial debug epoch")
            || normalized.contains("debug epoch is partially")
        {
            (
                ApiErrorCode::DebugEpochPartial,
                ApiErrorCategory::State,
                true,
            )
        } else if normalized.contains("malformed")
            || normalized.contains("invalid ")
            || normalized.contains("protocol")
            || normalized.contains("unknown field")
            || normalized.contains("missing field")
            || normalized.contains("must ")
        {
            (
                ApiErrorCode::ValidationError,
                ApiErrorCategory::Validation,
                false,
            )
        } else if normalized.contains("outside")
            || normalized.contains("unauthorized")
            || normalized.contains("denied")
            || normalized.contains("requires an authenticated")
            || normalized.contains("may only")
        {
            (
                ApiErrorCode::Forbidden,
                ApiErrorCategory::Authorization,
                false,
            )
        } else if normalized.contains("not found")
            || normalized.contains("does not exist")
            || normalized.contains("unknown ")
        {
            (ApiErrorCode::NotFound, ApiErrorCategory::State, false)
        } else if normalized.contains("already")
            || normalized.contains("conflict")
            || normalized.contains("requires an active")
        {
            (ApiErrorCode::Conflict, ApiErrorCategory::State, false)
        } else {
            (
                ApiErrorCode::InternalError,
                ApiErrorCategory::Internal,
                false,
            )
        };
        Self::new(code, category, message, retryable, request_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_machine_codes_are_stably_serialized() {
        let required = [
            ApiErrorCode::Unauthenticated,
            ApiErrorCode::SessionExpired,
            ApiErrorCode::AccountSuspended,
            ApiErrorCode::Forbidden,
            ApiErrorCode::ValidationError,
            ApiErrorCode::NotFound,
            ApiErrorCode::Conflict,
            ApiErrorCode::ActiveProcessExists,
            ApiErrorCode::NodeOffline,
            ApiErrorCode::NoCapableNode,
            ApiErrorCode::TaskNotRestartable,
            ApiErrorCode::ArtifactUnavailable,
            ApiErrorCode::ArtifactLimitExceeded,
            ApiErrorCode::QuotaExceeded,
            ApiErrorCode::TemporaryCapacity,
            ApiErrorCode::DebugEpochPartial,
        ];
        let serialized = required
            .into_iter()
            .map(|code| serde_json::to_value(code).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            serialized,
            vec![
                "unauthenticated",
                "session_expired",
                "account_suspended",
                "forbidden",
                "validation_error",
                "not_found",
                "conflict",
                "active_process_exists",
                "node_offline",
                "no_capable_node",
                "task_not_restartable",
                "artifact_unavailable",
                "artifact_limit_exceeded",
                "quota_exceeded",
                "temporary_capacity",
                "debug_epoch_partial",
            ]
        );
    }

    #[test]
    fn message_classification_keeps_request_identity() {
        let error = ApiError::from_message(
            "request-17",
            "CLI session credential has expired; run login again",
        );
        assert_eq!(error.code, ApiErrorCode::SessionExpired);
        assert_eq!(error.category, ApiErrorCategory::Authentication);
        assert_eq!(error.request_id, "request-17");
        assert!(!error.retryable);
    }

    #[test]
    fn missing_node_capability_report_is_a_retryable_capability_error() {
        let error = ApiError::from_message("node-12", "node has no capability report");
        assert_eq!(error.code, ApiErrorCode::NoCapableNode);
        assert_eq!(error.category, ApiErrorCategory::Availability);
        assert!(error.retryable);
    }
}
