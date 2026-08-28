use clusterflux_core::{
    ApiError, BrowserLoginFlow, CredentialKind, Digest, ProjectId, TenantId, UserId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum LoginRequest {
    BeginOidcBrowserLogin {},
    BeginWebBrowserLogin {},
    CancelWebBrowserLogin {
        transaction_id: String,
    },
    PollOidcBrowserLogin {
        transaction_id: String,
        polling_secret: String,
    },
    ExchangeWebLoginHandoff {
        transaction_id: String,
        handoff_code: String,
    },
}

impl std::fmt::Debug for LoginRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeginOidcBrowserLogin {} => {
                formatter.write_str("LoginRequest::BeginOidcBrowserLogin")
            }
            Self::BeginWebBrowserLogin {} => {
                formatter.write_str("LoginRequest::BeginWebBrowserLogin")
            }
            Self::CancelWebBrowserLogin { .. } => formatter
                .debug_struct("LoginRequest::CancelWebBrowserLogin")
                .field("transaction_id", &"[REDACTED]")
                .finish(),
            Self::PollOidcBrowserLogin { .. } => formatter
                .debug_struct("LoginRequest::PollOidcBrowserLogin")
                .field("transaction_id", &"[REDACTED]")
                .field("polling_secret", &"[REDACTED]")
                .finish(),
            Self::ExchangeWebLoginHandoff { .. } => formatter
                .debug_struct("LoginRequest::ExchangeWebLoginHandoff")
                .field("transaction_id", &"[REDACTED]")
                .field("handoff_code", &"[REDACTED]")
                .finish(),
        }
    }
}

impl LoginRequest {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::BeginOidcBrowserLogin {} => "begin_oidc_browser_login",
            Self::BeginWebBrowserLogin {} => "begin_web_browser_login",
            Self::CancelWebBrowserLogin { .. } => "cancel_web_browser_login",
            Self::PollOidcBrowserLogin { .. } => "poll_oidc_browser_login",
            Self::ExchangeWebLoginHandoff { .. } => "exchange_web_login_handoff",
        }
    }

    pub fn validate_external_inputs(&self) -> Result<(), String> {
        match self {
            Self::BeginOidcBrowserLogin {} | Self::BeginWebBrowserLogin {} => Ok(()),
            Self::CancelWebBrowserLogin { transaction_id } => {
                validate_login_token("login transaction id", transaction_id, 256)
            }
            Self::PollOidcBrowserLogin {
                transaction_id,
                polling_secret,
            } => {
                validate_login_token("login transaction id", transaction_id, 256)?;
                validate_login_token("login polling secret", polling_secret, 256)
            }
            Self::ExchangeWebLoginHandoff {
                transaction_id,
                handoff_code,
            } => {
                validate_login_token("login transaction id", transaction_id, 256)?;
                validate_login_token("web login handoff code", handoff_code, 256)
            }
        }
    }
}

fn validate_login_token(label: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    clusterflux_core::validate_opaque_token(value, max_bytes)
        .map_err(|error| format!("{label} is invalid: {error}"))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcTokenExchangeSummary {
    pub token_endpoint: String,
    pub token_type: String,
    pub received_access_token: bool,
    pub received_id_token: bool,
    pub retained_provider_tokens: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedNormalizedIdentitySummary {
    pub source: String,
    pub external_identity_provider: String,
    pub external_provider_protocol: String,
    pub authentik_subject_present: bool,
    pub external_subject_present: bool,
    pub email_claim_present: bool,
    pub email_verified: bool,
    pub ambiguous_external_identity: bool,
    pub provider_trusted_by_authentik: bool,
    pub consumed_normalized_authentik_identity: bool,
    pub provider_specific_tokens_consumed_directly: bool,
    pub provider_tokens_retained: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedSignupCheckSummary {
    pub normalized_identity_source: String,
    pub external_identity_provider: String,
    pub external_provider_protocol: String,
    pub approved_external_identity_provider_required: bool,
    pub approved_external_identity_provider: bool,
    pub required_claims_present: bool,
    pub ambiguous_identity: bool,
    pub email_policy_checked: bool,
    pub email_verified_or_provider_trusted: bool,
    pub hosted_signup_policy_checked: bool,
    pub clusterflux_native_password_signup_allowed: bool,
    pub private_failure_details_exposed: bool,
    pub default_project_created_or_linked: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedLoginSession {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub user: UserId,
    pub browser_credential_kind: CredentialKind,
    pub cli_session_credential_kind: CredentialKind,
    pub cli_session_secret: String,
    pub cli_session_secret_digest: Digest,
    pub expires_at_epoch_seconds: u64,
    pub flow: BrowserLoginFlow,
    pub oidc_token_exchange: OidcTokenExchangeSummary,
    pub normalized_identity: HostedNormalizedIdentitySummary,
    pub signup_checks: HostedSignupCheckSummary,
    pub provider_tokens_sent_to_nodes: bool,
}

impl std::fmt::Debug for HostedLoginSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostedLoginSession")
            .field("tenant", &self.tenant)
            .field("project", &self.project)
            .field("user", &self.user)
            .field("browser_credential_kind", &self.browser_credential_kind)
            .field(
                "cli_session_credential_kind",
                &self.cli_session_credential_kind,
            )
            .field("cli_session_secret", &"[REDACTED]")
            .field("cli_session_secret_digest", &self.cli_session_secret_digest)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .field("flow", &self.flow)
            .field("oidc_token_exchange", &self.oidc_token_exchange)
            .field("normalized_identity", &self.normalized_identity)
            .field("signup_checks", &self.signup_checks)
            .field(
                "provider_tokens_sent_to_nodes",
                &self.provider_tokens_sent_to_nodes,
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebBrowserSession {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub user: UserId,
    pub session_secret: String,
    pub expires_at_epoch_seconds: u64,
}

impl std::fmt::Debug for WebBrowserSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebBrowserSession")
            .field("tenant", &self.tenant)
            .field("project", &self.project)
            .field("user", &self.user)
            .field("session_secret", &"[REDACTED]")
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .finish()
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LoginResponse {
    OidcBrowserLoginStarted {
        transaction_id: String,
        polling_secret: String,
        authorization_url: String,
        expires_at_epoch_seconds: u64,
    },
    WebBrowserLoginStarted {
        transaction_id: String,
        authorization_url: String,
        expires_at_epoch_seconds: u64,
    },
    WebBrowserLoginCancelled {},
    OidcBrowserLoginPending {
        transaction_id: String,
    },
    OidcBrowserSession {
        session: Box<HostedLoginSession>,
    },
    WebBrowserSession {
        session: WebBrowserSession,
    },
    Error {
        #[serde(flatten)]
        error: ApiError,
    },
}

impl std::fmt::Debug for LoginResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OidcBrowserLoginStarted {
                transaction_id,
                authorization_url,
                expires_at_epoch_seconds,
                ..
            } => formatter
                .debug_struct("LoginResponse::OidcBrowserLoginStarted")
                .field("transaction_id", transaction_id)
                .field("polling_secret", &"[REDACTED]")
                .field("authorization_url", authorization_url)
                .field("expires_at_epoch_seconds", expires_at_epoch_seconds)
                .finish(),
            Self::WebBrowserLoginStarted {
                transaction_id,
                authorization_url,
                expires_at_epoch_seconds,
            } => formatter
                .debug_struct("LoginResponse::WebBrowserLoginStarted")
                .field("transaction_id", transaction_id)
                .field("authorization_url", authorization_url)
                .field("expires_at_epoch_seconds", expires_at_epoch_seconds)
                .finish(),
            Self::WebBrowserLoginCancelled {} => {
                formatter.write_str("LoginResponse::WebBrowserLoginCancelled")
            }
            Self::OidcBrowserLoginPending { transaction_id } => formatter
                .debug_struct("LoginResponse::OidcBrowserLoginPending")
                .field("transaction_id", transaction_id)
                .finish(),
            Self::OidcBrowserSession { session } => formatter
                .debug_struct("LoginResponse::OidcBrowserSession")
                .field("session", session)
                .finish(),
            Self::WebBrowserSession { session } => formatter
                .debug_struct("LoginResponse::WebBrowserSession")
                .field("session", session)
                .finish(),
            Self::Error { error } => formatter
                .debug_struct("LoginResponse::Error")
                .field("error", error)
                .finish(),
        }
    }
}

impl LoginResponse {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::OidcBrowserLoginStarted { .. } => "oidc_browser_login_started",
            Self::WebBrowserLoginStarted { .. } => "web_browser_login_started",
            Self::WebBrowserLoginCancelled {} => "web_browser_login_cancelled",
            Self::OidcBrowserLoginPending { .. } => "oidc_browser_login_pending",
            Self::OidcBrowserSession { .. } => "oidc_browser_session",
            Self::WebBrowserSession { .. } => "web_browser_session",
            Self::Error { .. } => "error",
        }
    }

    pub fn error(request_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Error {
            error: ApiError::from_message(request_id, message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_secrets_are_redacted_from_debug_output() {
        let request = LoginRequest::PollOidcBrowserLogin {
            transaction_id: "transaction-secret".to_owned(),
            polling_secret: "polling-secret".to_owned(),
        };
        let response = LoginResponse::OidcBrowserLoginStarted {
            transaction_id: "transaction-public".to_owned(),
            polling_secret: "response-polling-secret".to_owned(),
            authorization_url: "https://auth.example/authorize".to_owned(),
            expires_at_epoch_seconds: 1,
        };

        let rendered = format!("{request:?} {response:?}");
        assert!(!rendered.contains("transaction-secret"));
        assert!(!rendered.contains("polling-secret"));
        assert!(!rendered.contains("response-polling-secret"));
        assert!(rendered.contains("[REDACTED]"));
    }
}
