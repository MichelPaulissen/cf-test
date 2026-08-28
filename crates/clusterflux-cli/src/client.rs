use anyhow::{Context, Result};
use clusterflux_client::{
    endpoint_identity, endpoint_is_loopback, ControlTransportError, LoginSession, ProtocolSession,
};
use clusterflux_protocol::{
    AuthenticatedCoordinatorRequest, CoordinatorRequest, CoordinatorResponse, LoginRequest,
    LoginResponse,
};
use serde_json::{json, Value};

use crate::config::StoredCliSession;
use crate::CliScopeArgs;

pub(crate) struct JsonLineSession {
    inner: ProtocolSession,
}

pub(crate) struct BrowserLoginSession {
    inner: LoginSession,
}

impl JsonLineSession {
    pub(crate) fn connect(addr: &str) -> Result<Self> {
        let inner = ProtocolSession::connect(addr, "cli")
            .with_context(|| format!("failed to connect to coordinator {addr}"))?;
        Ok(Self { inner })
    }

    pub(crate) fn request(&mut self, request: CoordinatorRequest) -> Result<CoordinatorResponse> {
        let response = self.request_allow_error(request)?;
        if let CoordinatorResponse::Error { error } = response {
            return Err(anyhow::Error::new(error));
        }
        Ok(response)
    }

    pub(crate) fn request_allow_error(
        &mut self,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse> {
        Ok(self.inner.request_allow_error(&request)?)
    }

    pub(crate) fn request_typed(
        &mut self,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse> {
        self.request(request)
    }

    pub(crate) fn requests(&self) -> u64 {
        self.inner.requests()
    }
}

impl BrowserLoginSession {
    pub(crate) fn connect(addr: &str) -> Result<Self> {
        let inner = LoginSession::connect(addr, "cli-login")
            .with_context(|| format!("failed to connect to hosted login endpoint {addr}"))?;
        Ok(Self { inner })
    }

    pub(crate) fn request_allow_transport_error(
        &mut self,
        request: &LoginRequest,
    ) -> std::result::Result<LoginResponse, ControlTransportError> {
        self.inner.request_allow_error(request)
    }

    pub(crate) fn requests(&self) -> u64 {
        self.inner.requests()
    }
}

pub(crate) fn control_endpoint_identity(endpoint: &str) -> Result<String> {
    endpoint_identity(endpoint).map_err(anyhow::Error::from)
}

pub(crate) fn authenticated_or_local_trusted_request(
    coordinator: &str,
    stored_session: Option<&StoredCliSession>,
    local_trusted_request: CoordinatorRequest,
) -> Result<CoordinatorRequest> {
    if let Some(session_secret) = stored_session_for_coordinator(coordinator, stored_session)
        .and_then(|session| session.session_secret.as_ref())
    {
        let request =
            AuthenticatedCoordinatorRequest::try_from(local_trusted_request).map_err(|error| {
                anyhow::anyhow!(
                    "CLI request is not available through an authenticated session: {error}"
                )
            })?;
        Ok(CoordinatorRequest::Authenticated {
            session_secret: session_secret.clone(),
            request,
        })
    } else if is_loopback_coordinator(coordinator) {
        Ok(local_trusted_request)
    } else {
        Err(crate::errors::CliFailure::authentication_required(format!(
            "no authenticated CLI session matches coordinator {coordinator}"
        ))
        .with_coordinator(coordinator)
        .into())
    }
}

pub(crate) fn is_loopback_coordinator(coordinator: &str) -> bool {
    endpoint_is_loopback(coordinator)
}

pub(crate) fn stored_session_for_coordinator<'a>(
    coordinator: &str,
    stored_session: Option<&'a StoredCliSession>,
) -> Option<&'a StoredCliSession> {
    stored_session.filter(|session| {
        session.session_secret.is_some()
            && control_endpoint_identity(&session.coordinator).ok()
                == control_endpoint_identity(coordinator).ok()
    })
}

pub(crate) fn list_task_events_if_available_with_session(
    coordinator: Option<&str>,
    scope: &CliScopeArgs,
    process: Option<String>,
    stored_session: Option<&StoredCliSession>,
) -> Result<Option<Value>> {
    let Some(coordinator) = coordinator else {
        return Ok(None);
    };
    let mut session = JsonLineSession::connect(coordinator)?;
    let response = session.request(authenticated_or_local_trusted_request(
        coordinator,
        stored_session,
        CoordinatorRequest::ListTaskEvents {
            tenant: scope.tenant.clone(),
            project: scope.project.clone(),
            actor_user: scope.user.clone(),
            process,
        },
    )?)?;
    if !matches!(&response, CoordinatorResponse::TaskEvents { .. }) {
        anyhow::bail!("coordinator returned an unexpected task-events response");
    }
    Ok(Some(json!({
        "coordinator": coordinator,
        "response": serde_json::to_value(response)?,
        "coordinator_session_requests": session.requests(),
    })))
}

pub(crate) fn list_attached_nodes_if_available_with_session(
    coordinator: Option<&str>,
    scope: &CliScopeArgs,
    stored_session: Option<&StoredCliSession>,
) -> Result<Value> {
    let Some(coordinator) = coordinator else {
        return Ok(json!({
            "checked": false,
            "source": "no_coordinator",
            "count": 0,
            "online": 0,
            "response": null,
        }));
    };

    let mut session = JsonLineSession::connect(coordinator)?;
    let response = session.request(authenticated_or_local_trusted_request(
        coordinator,
        stored_session,
        CoordinatorRequest::ListNodeDescriptors {
            tenant: scope.tenant.clone(),
            project: scope.project.clone(),
            actor_user: scope.user.clone(),
        },
    )?)?;
    let (count, online) = match &response {
        CoordinatorResponse::NodeDescriptors { descriptors, .. } => (
            descriptors.len(),
            descriptors
                .iter()
                .filter(|descriptor| descriptor.online)
                .count(),
        ),
        _ => anyhow::bail!("coordinator returned an unexpected node-list response"),
    };

    Ok(json!({
        "checked": true,
        "source": "coordinator",
        "coordinator": coordinator,
        "count": count,
        "online": online,
        "response": serde_json::to_value(response)?,
        "coordinator_session_requests": session.requests(),
    }))
}
