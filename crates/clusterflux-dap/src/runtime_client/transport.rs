use anyhow::{anyhow, Result};
use clusterflux_client::ProtocolSession;
use clusterflux_protocol::{
    AuthenticatedCoordinatorRequest, CoordinatorRequest, CoordinatorResponse,
};

use crate::virtual_model::AdapterState;

pub(crate) fn client_user_request(
    state: &AdapterState,
    request: CoordinatorRequest,
) -> CoordinatorRequest {
    let Some(session_secret) = state.client_session_secret.as_deref() else {
        return request;
    };
    let request = AuthenticatedCoordinatorRequest::try_from(request)
        .expect("typed DAP request must map to an authenticated coordinator request");
    CoordinatorRequest::Authenticated {
        session_secret: session_secret.to_owned(),
        request,
    }
}

pub(super) struct CoordinatorSession {
    session: ProtocolSession,
}

impl CoordinatorSession {
    pub(super) fn connect(addr: &str) -> Result<Self> {
        Ok(Self {
            session: ProtocolSession::connect(addr, "dap")?,
        })
    }

    pub(super) fn request(&mut self, request: CoordinatorRequest) -> Result<CoordinatorResponse> {
        let response = self.request_allow_error(request)?;
        if let CoordinatorResponse::Error { error } = response {
            return Err(anyhow!("{}", error.message));
        }
        Ok(response)
    }

    pub(super) fn request_allow_error(
        &mut self,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse> {
        Ok(self.session.request_allow_error(&request)?)
    }
}

pub(super) fn coordinator_request(
    addr: &str,
    request: CoordinatorRequest,
) -> Result<CoordinatorResponse> {
    CoordinatorSession::connect(addr)?.request(request)
}

pub(super) fn coordinator_request_allow_error(
    addr: &str,
    request: CoordinatorRequest,
) -> Result<CoordinatorResponse> {
    CoordinatorSession::connect(addr)?.request_allow_error(request)
}
