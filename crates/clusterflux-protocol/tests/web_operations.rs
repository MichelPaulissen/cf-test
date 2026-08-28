use std::collections::BTreeSet;

use clusterflux_protocol::{
    AuthenticatedCoordinatorRequest, CoordinatorResponse, LoginRequest, LoginResponse,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct OperationFixture {
    operation: String,
    boundary: String,
    request: Value,
    response: Value,
}

#[test]
fn website_operation_contract_fixtures_cover_every_typed_request_and_response() {
    let fixtures: Vec<OperationFixture> =
        serde_json::from_str(include_str!("fixtures/web_operations.json")).unwrap();
    let expected = BTreeSet::from([
        "abort_process",
        "auth_status",
        "begin_oidc_browser_login",
        "begin_web_browser_login",
        "cancel_web_browser_login",
        "cancel_process",
        "create_artifact_download_link",
        "create_debug_epoch",
        "create_node_enrollment_grant",
        "create_project",
        "debug_attach",
        "exchange_web_login_handoff",
        "get_artifact",
        "inspect_debug_epoch",
        "list_agent_public_keys",
        "list_artifacts",
        "list_node_summaries",
        "list_process_summaries",
        "list_projects",
        "list_recent_logs",
        "list_task_events",
        "list_task_snapshots",
        "poll_oidc_browser_login",
        "quota_status",
        "register_agent_public_key",
        "resolve_task_failure",
        "restart_task",
        "resume_debug_epoch",
        "revoke_agent_public_key",
        "revoke_artifact_download_link",
        "revoke_cli_session",
        "revoke_node_credential",
        "rotate_agent_public_key",
        "select_project",
    ])
    .into_iter()
    .map(str::to_owned)
    .collect();
    let mut observed = BTreeSet::new();

    for fixture in fixtures {
        assert_eq!(fixture.request["type"], fixture.operation);
        match fixture.boundary.as_str() {
            "control" => {
                let typed: AuthenticatedCoordinatorRequest =
                    serde_json::from_value(fixture.request.clone()).unwrap();
                assert_eq!(serde_json::to_value(typed).unwrap(), fixture.request);
                let response: CoordinatorResponse =
                    serde_json::from_value(fixture.response.clone()).unwrap_or_else(|error| {
                        panic!("{} response fixture is invalid: {error}", fixture.operation)
                    });
                assert!(!matches!(&response, CoordinatorResponse::Error { .. }));
                assert_eq!(serde_json::to_value(response).unwrap(), fixture.response);
            }
            "login" => {
                let typed: LoginRequest = serde_json::from_value(fixture.request.clone()).unwrap();
                assert_eq!(serde_json::to_value(typed).unwrap(), fixture.request);
                let response: LoginResponse = serde_json::from_value(fixture.response.clone())
                    .unwrap_or_else(|error| {
                        panic!("{} response fixture is invalid: {error}", fixture.operation)
                    });
                assert!(!matches!(&response, LoginResponse::Error { .. }));
                assert_eq!(serde_json::to_value(response).unwrap(), fixture.response);
            }
            boundary => panic!("unknown fixture boundary {boundary}"),
        }
        assert!(observed.insert(fixture.operation));
    }
    assert_eq!(observed, expected);
}
