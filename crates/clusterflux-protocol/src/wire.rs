use crate::{CoordinatorRequest, CoordinatorRequestEnvelope, LoginRequest, LoginRequestEnvelope};

pub fn coordinator_wire_request(
    request_id: impl Into<String>,
    payload: CoordinatorRequest,
) -> CoordinatorRequestEnvelope {
    CoordinatorRequestEnvelope::new(request_id, payload)
}

pub fn login_wire_request(
    request_id: impl Into<String>,
    payload: LoginRequest,
) -> LoginRequestEnvelope {
    LoginRequestEnvelope::new(request_id, payload)
}

#[cfg(test)]
mod tests {
    use clusterflux_core::NodeSignedRequest;
    use serde_json::json;

    use super::*;

    #[test]
    fn coordinator_wire_request_wraps_payload_without_exposing_secret_metadata() {
        let envelope = serde_json::to_value(coordinator_wire_request(
            "cli-1",
            CoordinatorRequest::Authenticated {
                session_secret: "secret-value".to_owned(),
                request: crate::AuthenticatedCoordinatorRequest::ListProjects,
            },
        ))
        .unwrap();

        assert_eq!(envelope["type"], crate::COORDINATOR_WIRE_REQUEST_TYPE);
        assert_eq!(
            envelope["protocol_version"],
            crate::COORDINATOR_PROTOCOL_VERSION
        );
        assert_eq!(envelope["request_id"], "cli-1");
        assert_eq!(envelope["operation"], "authenticated");
        assert_eq!(envelope["authentication"]["kind"], "cli_session");
        assert_eq!(
            envelope["authentication"]["request_operation"],
            "list_projects"
        );
        assert_eq!(envelope["authentication"].get("session_secret"), None);
        assert_eq!(envelope["payload"]["session_secret"], "secret-value");
    }

    #[test]
    fn coordinator_wire_request_describes_signature_metadata() {
        let envelope = serde_json::to_value(coordinator_wire_request(
            "node-1",
            CoordinatorRequest::SignedNode {
                node: "node-a".to_owned(),
                node_signature: NodeSignedRequest {
                    nonce: "nonce".to_owned(),
                    issued_at_epoch_seconds: 1,
                    signature: "ed25519:sig".to_owned(),
                    assignment_authority: None,
                    operation_id: None,
                },
                request: Box::new(CoordinatorRequest::PollNodeAssignment {
                    tenant: "tenant-a".to_owned(),
                    project: "project-a".to_owned(),
                    node: "node-a".to_owned(),
                    accept_system_tasks: true,
                    accept_process_tasks: true,
                    active_assignment: None,
                }),
            },
        ))
        .unwrap();

        assert_eq!(
            envelope["authentication"],
            json!({ "kind": "node_signature", "node": "node-a" })
        );
    }

    #[test]
    fn login_wire_request_uses_the_same_versioned_envelope() {
        let envelope = serde_json::to_value(login_wire_request(
            "login-1",
            LoginRequest::CancelWebBrowserLogin {
                transaction_id: "login-transaction".to_owned(),
            },
        ))
        .unwrap();

        assert_eq!(envelope["operation"], "cancel_web_browser_login");
        assert_eq!(envelope["authentication"], json!({ "kind": "none" }));
        assert_eq!(
            envelope["payload"],
            json!({
                "type": "cancel_web_browser_login",
                "transaction_id": "login-transaction"
            })
        );
    }

    #[test]
    fn typed_envelopes_reject_mismatched_authentication_metadata() {
        let mut coordinator = coordinator_wire_request("request-1", CoordinatorRequest::Ping);
        coordinator.authentication = Some(crate::CoordinatorAuthentication::CliSession {
            session: true,
            request_operation: "ping".to_owned(),
        });
        assert!(coordinator
            .into_parts()
            .unwrap_err()
            .contains("authentication metadata does not match"));

        let mut login = login_wire_request("request-2", LoginRequest::BeginWebBrowserLogin {});
        login.authentication = Some(crate::CoordinatorAuthentication::NodeSignature {
            node: "node-a".to_owned(),
        });
        assert!(login
            .into_parts()
            .unwrap_err()
            .contains("authentication metadata does not match"));
    }
}
