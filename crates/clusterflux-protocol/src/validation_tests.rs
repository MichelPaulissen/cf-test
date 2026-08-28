use super::*;

#[test]
fn auth_status_from_an_older_coordinator_has_empty_release_capabilities() {
    let response: CoordinatorResponse = serde_json::from_value(serde_json::json!({
        "type": "auth_status",
        "tenant": "tenant",
        "project": "project",
        "actor": "user",
        "authenticated": true,
        "account_status": "active",
        "suspended": false,
        "disabled": false,
        "deleted": false,
        "manual_review": false,
        "sanitized_reason": null,
        "next_actions": [],
        "sensitive_moderation_details_exposed": false,
        "signup_failure_details_exposed": false
    }))
    .unwrap();

    let CoordinatorResponse::AuthStatus {
        coordinator_version,
        workflow_sdk_version,
        ..
    } = response
    else {
        panic!("expected auth status");
    };
    assert!(coordinator_version.is_empty());
    assert!(workflow_sdk_version.is_empty());
}

#[cfg(test)]
mod external_identifier_tests {
    use super::*;

    fn valid_task_spec() -> TaskSpec {
        TaskSpec {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process: ProcessId::from("process"),
            task_definition: TaskDefinitionId::from("compile"),
            task_instance: TaskInstanceId::from("compile-1"),
            dispatch: clusterflux_core::TaskDispatch::CoordinatorNodeWasm {
                export: Some("compile".to_owned()),
                abi: clusterflux_core::WasmExportAbi::TaskV1,
            },
            environment_id: Some("linux-rootless".to_owned()),
            environment: None,
            environment_digest: None,
            required_capabilities: Default::default(),
            dependency_cache: None,
            source_snapshot: None,
            source_revision: None,
            required_artifacts: vec![ArtifactId::from("input-artifact")],
            args: Vec::new(),
            requested_secrets: Vec::new(),
            vfs_epoch: 1,
            failure_policy: Default::default(),
            bundle_digest: None,
        }
    }

    fn validation_error(value: serde_json::Value) -> String {
        match serde_json::from_value::<CoordinatorRequest>(value) {
            Ok(request) => request
                .validate_external_identifiers()
                .expect_err("request should contain one malformed external identifier"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn nested_authenticated_identifiers_are_validated() {
        let request = CoordinatorRequest::Authenticated {
            session_secret: "cli_session_valid".to_owned(),
            request: AuthenticatedCoordinatorRequest::AbortProcess {
                process: "bad process".to_owned(),
                launch_attempt: Some("attempt".to_owned()),
            },
        };
        let error = request.validate_external_identifiers().unwrap_err();
        assert!(error.contains("request.request.process"));
    }

    #[test]
    fn repository_trigger_and_delivery_page_inputs_are_strictly_bounded() {
        let trigger = |git_ref: &str, commit: Option<&str>| CoordinatorRequest::Authenticated {
            session_secret: "session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::TriggerAutomatedRun {
                repository: "github:owner/repository".to_owned(),
                git_ref: git_ref.to_owned(),
                commit: commit.map(str::to_owned),
            },
        };
        trigger(
            "refs/heads/main",
            Some("0123456789abcdef0123456789abcdef01234567"),
        )
        .validate_external_identifiers()
        .unwrap();
        assert!(trigger("main", None)
            .validate_external_identifiers()
            .unwrap_err()
            .contains("must identify a branch or tag"));
        assert!(trigger("refs/heads/main", Some("not-a-sha"))
            .validate_external_identifiers()
            .unwrap_err()
            .contains("commit is invalid"));

        let deliveries = |limit| CoordinatorRequest::Authenticated {
            session_secret: "session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListWebhookDeliveries {
                cursor: None,
                limit,
            },
        };
        deliveries(100).validate_external_identifiers().unwrap();
        for invalid in [0, 101] {
            assert!(deliveries(invalid)
                .validate_external_identifiers()
                .unwrap_err()
                .contains("pagination limit"));
        }
    }

    #[test]
    fn opaque_secrets_are_bounded_as_tokens_instead_of_object_ids() {
        let request = CoordinatorRequest::Authenticated {
            session_secret: "opaque secret/+==".to_owned(),
            request: AuthenticatedCoordinatorRequest::AuthStatus,
        };
        request.validate_external_identifiers().unwrap();

        let mut request = request;
        let CoordinatorRequest::Authenticated { session_secret, .. } = &mut request else {
            unreachable!()
        };
        *session_secret = "bad\0secret".to_owned();
        let error = request.validate_external_identifiers().unwrap_err();
        assert!(error.contains("malformed external token request.session_secret"));
    }

    #[test]
    fn real_protocol_variants_reject_exactly_one_malformed_nested_identifier() {
        let launch = CoordinatorRequest::LaunchTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: Some("user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            task_spec: valid_task_spec(),
            wait_for_node: false,
            artifact_path: "/vfs/artifacts/output".to_owned(),
            wasm_module_base64: "AGFzbQEAAAA=".to_owned(),
        };

        let mut malformed_definition = serde_json::to_value(&launch).unwrap();
        malformed_definition["task_spec"]["task_definition"] =
            serde_json::Value::String("bad task definition!".to_owned());
        let error = validation_error(malformed_definition);
        assert!(error.contains("TaskDefinitionId is invalid"));

        let mut malformed_artifact = serde_json::to_value(&launch).unwrap();
        malformed_artifact["task_spec"]["required_artifacts"][0] =
            serde_json::Value::String("bad artifact!".to_owned());
        let error = validation_error(malformed_artifact);
        assert!(error.contains("ArtifactId is invalid"));
    }

    #[test]
    fn signed_and_authenticated_real_variants_validate_scoped_ids_and_tokens() {
        let cases = [
            CoordinatorRequest::Authenticated {
                session_secret: "session-secret".to_owned(),
                request: AuthenticatedCoordinatorRequest::AbortProcess {
                    process: "bad process!".to_owned(),
                    launch_attempt: Some("attempt".to_owned()),
                },
            },
            CoordinatorRequest::StartProcess {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                actor_user: None,
                actor_agent: Some("bad agent!".to_owned()),
                agent_public_key_fingerprint: Some(Digest::sha256("agent")),
                agent_signature: Some(AgentSignedRequest {
                    nonce: "agent-nonce".to_owned(),
                    issued_at_epoch_seconds: 1,
                    signature: "ed25519:syntactically-bounded".to_owned(),
                }),
                process: "process".to_owned(),
                launch_attempt: Some("attempt".to_owned()),
                restart: false,
            },
            CoordinatorRequest::NodeHeartbeat {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: "bad node!".to_owned(),
                node_signature: Some(NodeSignedRequest {
                    nonce: "node-nonce".to_owned(),
                    issued_at_epoch_seconds: 1,
                    signature: "ed25519:syntactically-bounded".to_owned(),
                    assignment_authority: None,
                    operation_id: None,
                }),
            },
            CoordinatorRequest::SignedNode {
                node: "node".to_owned(),
                node_signature: NodeSignedRequest {
                    nonce: "node-nonce".to_owned(),
                    issued_at_epoch_seconds: 1,
                    signature: "ed25519:syntactically-bounded".to_owned(),
                    assignment_authority: None,
                    operation_id: None,
                },
                request: Box::new(CoordinatorRequest::PollNodeAssignment {
                    tenant: "tenant".to_owned(),
                    project: "bad project!".to_owned(),
                    node: "node".to_owned(),
                    accept_system_tasks: true,
                    accept_process_tasks: true,
                    active_assignment: None,
                }),
            },
            CoordinatorRequest::AbortProcess {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                actor_user: "user".to_owned(),
                process: "process".to_owned(),
                launch_attempt: Some("bad attempt!".to_owned()),
            },
        ];

        for request in cases {
            let error = request.validate_external_identifiers().unwrap_err();
            assert!(
                error.contains("malformed external identifier"),
                "unexpected validation error for {request:?}: {error}"
            );
        }
    }

    #[test]
    fn unsigned_workflow_requests_omit_absent_actor_fields() {
        let request = CoordinatorRequest::StartProcess {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process".to_owned(),
            launch_attempt: None,
            restart: false,
        };
        let value = serde_json::to_value(request).unwrap();
        for field in [
            "actor_user",
            "actor_agent",
            "agent_public_key_fingerprint",
            "agent_signature",
        ] {
            assert_eq!(
                value.get(field),
                None,
                "unexpected null actor field {field}"
            );
        }
    }

    #[test]
    fn signed_request_nonces_are_validated_as_opaque_tokens() {
        let agent_request = CoordinatorRequest::StartProcess {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: Some("agent".to_owned()),
            agent_public_key_fingerprint: Some(Digest::sha256("agent")),
            agent_signature: Some(AgentSignedRequest {
                nonce: String::new(),
                issued_at_epoch_seconds: 1,
                signature: "ed25519:syntactically-bounded".to_owned(),
            }),
            process: "process".to_owned(),
            launch_attempt: Some("attempt".to_owned()),
            restart: false,
        };
        let error = agent_request.validate_external_identifiers().unwrap_err();
        assert!(error.contains("malformed external token request.agent_signature.nonce"));

        let node_request = CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            node_signature: Some(NodeSignedRequest {
                nonce: String::new(),
                issued_at_epoch_seconds: 1,
                signature: "ed25519:syntactically-bounded".to_owned(),
                assignment_authority: None,
                operation_id: None,
            }),
        };
        let error = node_request.validate_external_identifiers().unwrap_err();
        assert!(error.contains("malformed external token request.node_signature.nonce"));
    }
}
