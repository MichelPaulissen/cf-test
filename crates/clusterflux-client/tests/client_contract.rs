use std::net::TcpListener;
use std::time::Duration;

use clusterflux_client::{
    ApiErrorCategory, ApiErrorCode, ArtifactId, ClientError, ClusterfluxClient, ControlTransport,
    MockTransport, ProjectId, RepositoryId, RunId, SessionCredential, TenantId, UserId,
    CLIENT_API_VERSION,
};
use clusterflux_client::{CONTROL_API_PATH, LOGIN_API_PATH};
use clusterflux_coordinator::service::CoordinatorService;
use serde_json::{json, Value};

#[tokio::test]
async fn mock_transport_exercises_typed_envelope_and_session_plumbing() {
    let transport = MockTransport::from_json_responses([json!({
        "type": "projects",
        "projects": [{
            "id": "project-one",
            "tenant": "tenant-one",
            "name": "Project one"
        }],
        "actor": "user-one"
    })
    .to_string()]);
    let client = ClusterfluxClient::with_transport(transport.clone())
        .with_session_credential(&SessionCredential::from_secret("test-session-secret"));

    let projects = client.list_projects().await.unwrap();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].id, ProjectId::from("project-one"));

    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].api_path, CONTROL_API_PATH);
    let envelope: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(envelope["protocol_version"], CLIENT_API_VERSION);
    assert_eq!(envelope["request_id"], "client-1");
    assert_eq!(envelope["operation"], "authenticated");
    assert_eq!(envelope["payload"]["type"], "authenticated");
    assert_eq!(envelope["payload"]["request"]["type"], "list_projects");
    assert_eq!(envelope["payload"]["session_secret"], "test-session-secret");
}

#[tokio::test]
async fn structured_errors_retain_machine_fields_and_originating_request_id() {
    let transport = MockTransport::from_json_responses([json!({
        "type": "error",
        "code": "account_suspended",
        "category": "authorization",
        "message": "account access is suspended",
        "retryable": false,
        "request_id": "client-1"
    })
    .to_string()]);
    let client = ClusterfluxClient::with_transport(transport)
        .with_session_credential(&SessionCredential::from_secret("test-session-secret"));

    let ClientError::Api(error) = client.account_status().await.unwrap_err() else {
        panic!("expected typed API error");
    };
    assert_eq!(error.code, ApiErrorCode::AccountSuspended);
    assert_eq!(error.category, ApiErrorCategory::Authorization);
    assert_eq!(error.request_id, "client-1");
    assert!(!error.retryable);
}

#[tokio::test]
async fn automation_helpers_send_exact_authenticated_request_shapes() {
    let response = |request_id: &str| {
        json!({
            "type": "error",
            "code": "not_found",
            "category": "state",
            "message": "not found",
            "retryable": false,
            "request_id": request_id
        })
        .to_string()
    };
    let transport = MockTransport::from_json_responses([
        response("client-1"),
        response("client-2"),
        response("client-3"),
    ]);
    let client = ClusterfluxClient::with_transport(transport.clone())
        .with_session_credential(&SessionCredential::from_secret("test-session-secret"));

    client
        .trigger_automated_run(
            RepositoryId::from("github:owner/repository"),
            "refs/heads/main".to_owned(),
            Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
        )
        .await
        .unwrap_err();
    client
        .list_webhook_deliveries_page(Some("42".to_owned()), 50)
        .await
        .unwrap_err();
    client
        .get_automated_run(RunId::from("run-1"))
        .await
        .unwrap_err();

    let requests = transport.requests();
    let payloads = requests
        .iter()
        .map(|request| {
            serde_json::from_slice::<Value>(&request.body).unwrap()["payload"]["request"].clone()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        payloads[0],
        json!({
            "type": "trigger_automated_run",
            "repository": "github:owner/repository",
            "git_ref": "refs/heads/main",
            "commit": "0123456789abcdef0123456789abcdef01234567"
        })
    );
    assert_eq!(
        payloads[1],
        json!({"type": "list_webhook_deliveries", "cursor": "42", "limit": 50})
    );
    assert_eq!(
        payloads[2],
        json!({"type": "get_automated_run", "run": "run-1"})
    );
}

#[tokio::test]
async fn browser_login_cancellation_uses_the_login_boundary_and_exact_transaction() {
    let transport = MockTransport::from_json_responses([
        json!({ "type": "web_browser_login_cancelled" }).to_string(),
    ]);
    let client = ClusterfluxClient::with_transport(transport.clone());

    client
        .cancel_browser_login("login-transaction")
        .await
        .unwrap();

    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].api_path, LOGIN_API_PATH);
    let envelope: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(envelope["operation"], "cancel_web_browser_login");
    assert_eq!(
        envelope["payload"],
        json!({
            "type": "cancel_web_browser_login",
            "transaction_id": "login-transaction"
        })
    );
}

#[tokio::test]
async fn a_mismatched_error_request_id_is_rejected_as_a_protocol_error() {
    let transport = MockTransport::from_json_responses([json!({
        "type": "error",
        "code": "validation_error",
        "category": "validation",
        "message": "bad request",
        "retryable": false,
        "request_id": "another-request"
    })
    .to_string()]);
    let client = ClusterfluxClient::with_transport(transport)
        .with_session_credential(&SessionCredential::from_secret("test-session-secret"));

    let ClientError::Protocol(message) = client.list_projects().await.unwrap_err() else {
        panic!("expected protocol error");
    };
    assert!(message.contains("does not match client-1"));
}

#[tokio::test]
async fn an_unexpected_success_variant_reports_the_originating_request_id() {
    let transport = MockTransport::from_json_responses([json!({
        "type": "projects",
        "projects": [],
        "actor": "user-one"
    })
    .to_string()]);
    let client = ClusterfluxClient::with_transport(transport)
        .with_session_credential(&SessionCredential::from_secret("test-session-secret"));

    let ClientError::UnexpectedResponse {
        request_id,
        expected,
        received,
    } = client.account_status().await.unwrap_err()
    else {
        panic!("expected typed unexpected-response error");
    };
    assert_eq!(request_id, "client-1");
    assert_eq!(expected, "auth_status");
    assert_eq!(received, "projects");
}

#[test]
fn session_credentials_are_redacted_from_debug_output() {
    let credential = SessionCredential::from_secret("must-not-appear");
    assert_eq!(format!("{credential:?}"), "SessionCredential([REDACTED])");
}

#[tokio::test]
async fn artifact_download_link_is_typed_metadata_without_a_byte_stream() {
    let link = json!({
        "artifact": "artifact-one",
        "artifact_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "artifact_size_bytes": 5,
        "source": { "RetainedNode": "node-one" },
        "url_path": "/artifacts/tenant-one/project-one/process-one/artifact-one",
        "scoped_token_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "expires_at_epoch_seconds": 1000,
        "tenant": "tenant-one",
        "project": "project-one",
        "process": "process-one",
        "actor": { "User": "user-one" },
        "max_bytes": 1024,
        "policy_context_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    });
    let transport = MockTransport::from_json_responses([
        json!({ "type": "artifact_download_link", "link": link.clone() }).to_string(),
        json!({ "type": "artifact_download_link_revoked", "link": link }).to_string(),
    ]);
    let client = ClusterfluxClient::with_transport(transport)
        .with_session_credential(&SessionCredential::from_secret("test-session-secret"));
    let link = client
        .create_artifact_download_link(ArtifactId::from("artifact-one"), 1024, 60)
        .await
        .unwrap();
    assert_eq!(link.artifact, ArtifactId::from("artifact-one"));
    client
        .revoke_artifact_download_link(ArtifactId::from("artifact-one"), link.scoped_token_digest)
        .await
        .unwrap();
}

#[tokio::test]
async fn typed_client_runs_against_the_real_strict_control_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut service = CoordinatorService::new(7);
        service
            .issue_cli_session(
                TenantId::from("tenant-one"),
                ProjectId::from("project-one"),
                UserId::from("user-one"),
                "real-endpoint-session",
                None,
            )
            .unwrap();
        let (stream, _) = listener.accept().unwrap();
        service.handle_stream(stream).unwrap();
    });

    let client = ClusterfluxClient::connect(format!("clusterflux+tcp://{address}"))
        .unwrap()
        .with_session_credential(&SessionCredential::from_secret("real-endpoint-session"));
    let projects = client.list_projects().await.unwrap();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].id, ProjectId::from("project-one"));
    let status = client.account_status().await.unwrap();
    assert!(status.authenticated);
    assert_eq!(status.actor, UserId::from("user-one"));

    drop(client);
    server.join().unwrap();
}

#[tokio::test]
async fn concurrent_requests_expand_the_bounded_pool_without_serializing() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        // Accept both connections before serving either request. This keeps
        // the first pool slot occupied long enough to prove that a concurrent
        // request expands the pool, even when the blocking executor is busy.
        let streams = (0..2)
            .map(|_| {
                let (stream, _) = listener.accept().unwrap();
                stream
            })
            .collect::<Vec<_>>();
        let handlers = streams
            .into_iter()
            .map(|stream| {
                std::thread::spawn(move || {
                    let mut service = CoordinatorService::new(7);
                    service
                        .issue_cli_session(
                            TenantId::from("tenant-one"),
                            ProjectId::from("project-one"),
                            UserId::from("user-one"),
                            "concurrent-session",
                            None,
                        )
                        .unwrap();
                    service.handle_stream(stream).unwrap();
                })
            })
            .collect::<Vec<_>>();
        for handler in handlers {
            handler.join().unwrap();
        }
    });

    let transport = ControlTransport::with_timeouts(
        format!("clusterflux+tcp://{address}"),
        Duration::from_secs(2),
        Duration::from_secs(5),
    )
    .unwrap();
    let client = ClusterfluxClient::with_transport(transport)
        .with_session_credential(&SessionCredential::from_secret("concurrent-session"));
    let (first, second) = tokio::join!(client.account_status(), client.account_status());
    assert!(first.unwrap().authenticated);
    assert!(second.unwrap().authenticated);

    drop(client);
    server.join().unwrap();
}
