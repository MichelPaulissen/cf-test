use super::*;

#[test]
fn service_creates_selects_and_lists_signed_in_user_projects() {
    let mut service = CoordinatorService::new(7);

    let CoordinatorResponse::ProjectCreated { project, actor } = service
        .handle_request(CoordinatorRequest::CreateProject {
            tenant: "tenant-a".to_owned(),
            actor_user: "user-a".to_owned(),
            project: "project-a".to_owned(),
            name: "Demo".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected project creation");
    };
    assert_eq!(actor, UserId::from("user-a"));
    assert_eq!(project.tenant, TenantId::from("tenant-a"));
    assert_eq!(project.id, ProjectId::from("project-a"));
    assert_eq!(project.name, "Demo");

    let CoordinatorResponse::ProjectSelected { project, actor } = service
        .handle_request(CoordinatorRequest::SelectProject {
            tenant: "tenant-a".to_owned(),
            actor_user: "user-a".to_owned(),
            project: "project-a".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected project selection");
    };
    assert_eq!(actor, UserId::from("user-a"));
    assert_eq!(project.id, ProjectId::from("project-a"));

    service
        .handle_request(CoordinatorRequest::CreateProject {
            tenant: "tenant-b".to_owned(),
            actor_user: "user-b".to_owned(),
            project: "project-b".to_owned(),
            name: "Other".to_owned(),
        })
        .unwrap();

    let CoordinatorResponse::Projects { projects, actor } = service
        .handle_request(CoordinatorRequest::ListProjects {
            tenant: "tenant-a".to_owned(),
            actor_user: "user-a".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected project list");
    };
    assert_eq!(actor, UserId::from("user-a"));
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].id, ProjectId::from("project-a"));

    let cross_tenant = service
        .handle_request(CoordinatorRequest::SelectProject {
            tenant: "tenant-a".to_owned(),
            actor_user: "user-a".to_owned(),
            project: "project-b".to_owned(),
        })
        .unwrap_err();
    assert!(cross_tenant.to_string().contains("tenant scope"));
}

#[test]
fn authenticated_envelope_derives_user_scope_from_cli_session() {
    let mut service = CoordinatorService::new(7);
    service
        .issue_cli_session(
            TenantId::from("tenant-a"),
            ProjectId::from("project-a"),
            UserId::from("user-a"),
            "cli-session-secret",
            None,
        )
        .unwrap();

    let CoordinatorResponse::AuthStatus {
        tenant,
        project,
        actor,
        authenticated,
        coordinator_version,
        workflow_sdk_version,
        ..
    } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::AuthStatus,
        })
        .unwrap()
    else {
        panic!("expected authenticated auth status");
    };
    assert_eq!(tenant, TenantId::from("tenant-a"));
    assert_eq!(project, ProjectId::from("project-a"));
    assert_eq!(actor, UserId::from("user-a"));
    assert!(authenticated);
    assert_eq!(coordinator_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        workflow_sdk_version,
        clusterflux_core::SUPPORTED_WORKFLOW_SDK_VERSION
    );

    let CoordinatorResponse::ProjectCreated { project, actor } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::CreateProject {
                project: "project-b".to_owned(),
                name: "From Session".to_owned(),
            },
        })
        .unwrap()
    else {
        panic!("expected authenticated project creation");
    };
    assert_eq!(project.tenant, TenantId::from("tenant-a"));
    assert_eq!(project.id, ProjectId::from("project-b"));
    assert_eq!(actor, UserId::from("user-a"));

    let CoordinatorResponse::Projects { projects, actor } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListProjects,
        })
        .unwrap()
    else {
        panic!("expected authenticated project list");
    };
    assert_eq!(actor, UserId::from("user-a"));
    assert_eq!(projects.len(), 2);
    assert!(projects
        .iter()
        .any(|project| project.id == ProjectId::from("project-a")));
    assert!(projects
        .iter()
        .any(|project| project.id == ProjectId::from("project-b")));

    let CoordinatorResponse::AgentPublicKey { record, actor } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::RegisterAgentPublicKey {
                agent: "agent-session".to_owned(),
                public_key: "agent-session-key-v1".to_owned(),
            },
        })
        .unwrap()
    else {
        panic!("expected authenticated agent key registration");
    };
    assert_eq!(actor, UserId::from("user-a"));
    assert_eq!(record.tenant, TenantId::from("tenant-a"));
    assert_eq!(record.project, ProjectId::from("project-a"));
    assert_eq!(record.user, UserId::from("user-a"));
    assert_eq!(record.agent, AgentId::from("agent-session"));

    let CoordinatorResponse::AgentPublicKeys { records, actor } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListAgentPublicKeys,
        })
        .unwrap()
    else {
        panic!("expected authenticated agent key list");
    };
    assert_eq!(actor, UserId::from("user-a"));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].project, ProjectId::from("project-a"));

    let CoordinatorResponse::AgentPublicKey { record, actor } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::RevokeAgentPublicKey {
                agent: "agent-session".to_owned(),
            },
        })
        .unwrap()
    else {
        panic!("expected authenticated agent key revocation");
    };
    assert_eq!(actor, UserId::from("user-a"));
    assert!(record.revoked);

    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant-a".to_owned(),
            project: "project-a".to_owned(),
            node: "session-node".to_owned(),
            public_key: test_node_public_key("session-node"),
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant-a".to_owned(),
            project: "project-a".to_owned(),
            node: "session-node".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: vec![],
            dependency_cache_digests: vec![],
            source_snapshots: vec![],
            artifact_locations: vec![],
            online: true,
        })
        .unwrap();
    let CoordinatorResponse::NodeDescriptors { descriptors, actor } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListNodeDescriptors,
        })
        .unwrap()
    else {
        panic!("expected authenticated node descriptor list");
    };
    assert_eq!(actor, UserId::from("user-a"));
    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].id, NodeId::from("session-node"));

    let CoordinatorResponse::TaskPlacement { placement } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::ScheduleTask {
                environment: None,
                environment_digest: None,
                required_capabilities: vec![Capability::Command],
                dependency_cache: None,
                source_snapshot: None,
                required_artifacts: vec![],
                prefer_node: Some("session-node".to_owned()),
            },
        })
        .unwrap()
    else {
        panic!("expected authenticated task placement");
    };
    assert_eq!(placement.node, NodeId::from("session-node"));

    let CoordinatorResponse::ProcessStarted {
        launch_attempt: None,
        process,
        actor,
        ..
    } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::StartProcess {
                launch_attempt: None,
                process: "vp-session".to_owned(),
                restart: false,
            },
        })
        .unwrap()
    else {
        panic!("expected authenticated process start");
    };
    assert_eq!(process, ProcessId::from("vp-session"));
    assert_eq!(actor.user, Some(UserId::from("user-a")));

    let denied_external_task = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::LaunchTask {
                task_spec: Box::new(test_task_spec(
                    "tenant-a",
                    "project-a",
                    "vp-session",
                    "task-session",
                    7,
                    [Capability::Command],
                )),
                wait_for_node: false,
                artifact_path: "/vfs/artifacts/session.txt".to_owned(),
                wasm_module_base64: test_wasm_module_base64(),
            },
        })
        .unwrap_err();
    assert!(denied_external_task
        .to_string()
        .contains("external callers may launch only EntrypointV1"));

    let CoordinatorResponse::TaskLaunched {
        process,
        task,
        actor,
        assignment,
        ..
    } = service
        .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
            task_spec: test_task_spec(
                "tenant-a",
                "project-a",
                "vp-session",
                "task-session",
                7,
                [Capability::Command],
            ),
            tenant: "tenant-a".to_owned(),
            project: "project-a".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            wait_for_node: false,
            artifact_path: "/vfs/artifacts/session.txt".to_owned(),
            wasm_module_base64: test_wasm_module_base64(),
        })
        .unwrap()
    else {
        panic!("expected authenticated task launch");
    };
    assert_eq!(process, ProcessId::from("vp-session"));
    assert_eq!(task, TaskInstanceId::from("task-session"));
    assert_eq!(actor.kind, "task");
    assert_eq!(assignment.tenant, TenantId::from("tenant-a"));
    assert_eq!(assignment.project, ProjectId::from("project-a"));

    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReconnectNode {
            tenant: "tenant-a".to_owned(),
            project: "project-a".to_owned(),
            node: "session-node".to_owned(),
            process: "vp-session".to_owned(),
            epoch: 7,
        })
        .unwrap();
    let artifact_bytes = "session artifact";
    service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant-a".to_owned(),
            project: "project-a".to_owned(),
            process: "vp-session".to_owned(),
            node: "session-node".to_owned(),
            task: "task-session".to_owned(),
            terminal_state: Some(TaskTerminalState::Completed),
            status_code: Some(0),
            stdout_bytes: artifact_bytes.len() as u64,
            stderr_bytes: 0,
            stdout_tail: artifact_bytes.to_owned(),
            stderr_tail: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: Some("/vfs/artifacts/session.txt".to_owned()),
            artifact_digest: Some(Digest::sha256(artifact_bytes)),
            artifact_size_bytes: Some(artifact_bytes.len() as u64),
            result: None,
        })
        .unwrap();

    let CoordinatorResponse::TaskEvents { events } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListTaskEvents {
                process: Some("vp-session".to_owned()),
            },
        })
        .unwrap()
    else {
        panic!("expected authenticated task event list");
    };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].tenant, TenantId::from("tenant-a"));
    assert_eq!(events[0].project, ProjectId::from("project-a"));

    service
        .issue_cli_session(
            TenantId::from("tenant-b"),
            ProjectId::from("project-victim"),
            UserId::from("user-b"),
            "victim-cli-session-secret",
            None,
        )
        .unwrap();
    service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "victim-cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::StartProcess {
                launch_attempt: None,
                process: "vp-victim".to_owned(),
                restart: false,
            },
        })
        .unwrap();
    let cross_tenant_events = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListTaskEvents {
                process: Some("vp-victim".to_owned()),
            },
        })
        .unwrap_err();
    assert!(cross_tenant_events
        .to_string()
        .contains("outside the virtual process tenant/project scope"));

    let CoordinatorResponse::ArtifactDownloadLink { link } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::CreateArtifactDownloadLink {
                artifact: "session.txt".to_owned(),
                max_bytes: 1024,
                ttl_seconds: 60,
            },
        })
        .unwrap()
    else {
        panic!("expected authenticated artifact link");
    };
    assert_eq!(link.tenant, TenantId::from("tenant-a"));
    assert_eq!(link.project, ProjectId::from("project-a"));
    assert_eq!(link.actor, Actor::User(UserId::from("user-a")));

    let CoordinatorResponse::ProcessCancellationRequested { process, .. } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::CancelProcess {
                process: "vp-session".to_owned(),
            },
        })
        .unwrap()
    else {
        panic!("expected authenticated process cancellation");
    };
    assert_eq!(process, ProcessId::from("vp-session"));

    let CoordinatorResponse::DebugAttach { actor, .. } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::DebugAttach {
                process: "vp-session".to_owned(),
            },
        })
        .unwrap()
    else {
        panic!("expected authenticated debug attach");
    };
    assert_eq!(actor, UserId::from("user-a"));

    let CoordinatorResponse::NodeCredentialRevoked {
        node,
        tenant,
        project,
        actor,
        descriptor_removed,
        ..
    } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::RevokeNodeCredential {
                node: "session-node".to_owned(),
            },
        })
        .unwrap()
    else {
        panic!("expected authenticated node credential revocation");
    };
    assert_eq!(node, NodeId::from("session-node"));
    assert_eq!(tenant, TenantId::from("tenant-a"));
    assert_eq!(project, ProjectId::from("project-a"));
    assert_eq!(actor, UserId::from("user-a"));
    assert!(descriptor_removed);

    let rejected = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "wrong-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::AuthStatus,
        })
        .unwrap_err();
    assert!(rejected.to_string().contains("not recognized"));

    let expired = service
        .issue_cli_session(
            TenantId::from("tenant-a"),
            ProjectId::from("project-b"),
            UserId::from("user-a"),
            "expired-cli-session-secret",
            Some(1),
        )
        .unwrap();
    assert_eq!(expired.expires_at_epoch_seconds, Some(1));
    let expired_rejected = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "expired-cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::AuthStatus,
        })
        .unwrap_err();
    assert!(expired_rejected.to_string().contains("expired"));

    let CoordinatorResponse::CliSessionRevoked {
        tenant,
        project,
        actor,
    } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::RevokeCliSession,
        })
        .unwrap()
    else {
        panic!("expected CLI session revocation");
    };
    assert_eq!(tenant, TenantId::from("tenant-a"));
    assert_eq!(project, ProjectId::from("project-a"));
    assert_eq!(actor, UserId::from("user-a"));

    let revoked_rejected = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "cli-session-secret".to_owned(),
            request: AuthenticatedCoordinatorRequest::AuthStatus,
        })
        .unwrap_err();
    assert!(revoked_rejected.to_string().contains("revoked"));
}

#[test]
fn service_reports_and_enforces_public_admin_tenant_suspension() {
    let mut service = CoordinatorService::new_with_admin_token(7, "admin-token");

    let CoordinatorResponse::AuthStatus {
        tenant,
        project,
        actor,
        authenticated,
        account_status,
        suspended,
        disabled,
        sanitized_reason,
        sensitive_moderation_details_exposed,
        signup_failure_details_exposed,
        ..
    } = service
        .handle_request(CoordinatorRequest::AuthStatus {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected auth status");
    };
    assert_eq!(tenant, TenantId::from("tenant"));
    assert_eq!(project, ProjectId::from("project"));
    assert_eq!(actor, UserId::from("user"));
    assert!(authenticated);
    assert_eq!(account_status, "active");
    assert!(!suspended);
    assert!(!disabled);
    assert!(sanitized_reason.is_none());
    assert!(!sensitive_moderation_details_exposed);
    assert!(!signup_failure_details_exposed);

    for (tenant, policy_name, expected_status, expected_reason) in [
        (
            "manual-tenant",
            "tenant:manual_review",
            "manual_review",
            "account or tenant is pending hosted review",
        ),
        (
            "disabled-tenant",
            "tenant:disabled",
            "disabled",
            "account or tenant is disabled by hosted policy",
        ),
        (
            "deleted-tenant",
            "tenant:deleted",
            "deleted",
            "account or tenant is no longer active",
        ),
    ] {
        service.coordinator.upsert_service_policy_record(
            TenantId::from(tenant),
            policy_name,
            Digest::from_parts([tenant.as_bytes(), policy_name.as_bytes()]),
        );
        let CoordinatorResponse::AuthStatus {
            account_status,
            suspended,
            disabled,
            deleted,
            manual_review,
            sanitized_reason,
            next_actions,
            sensitive_moderation_details_exposed,
            signup_failure_details_exposed,
            ..
        } = service
            .handle_request(CoordinatorRequest::AuthStatus {
                tenant: tenant.to_owned(),
                project: "project".to_owned(),
                actor_user: "user".to_owned(),
            })
            .unwrap()
        else {
            panic!("expected inactive auth status");
        };
        assert_eq!(account_status, expected_status);
        assert_eq!(suspended, expected_status == "suspended");
        assert_eq!(disabled, expected_status == "disabled");
        assert_eq!(deleted, expected_status == "deleted");
        assert_eq!(manual_review, expected_status == "manual_review");
        assert_eq!(sanitized_reason.as_deref(), Some(expected_reason));
        assert!(next_actions
            .iter()
            .any(|action| action.contains("hosted operator")));
        assert!(!sensitive_moderation_details_exposed);
        assert!(!signup_failure_details_exposed);
    }

    let (admin_proof, admin_nonce, issued_at_epoch_seconds) = test_admin_request(
        "admin-token",
        "admin_status",
        "tenant",
        "admin",
        "tenant",
        "admin-status-1",
    );
    let admin_status_request = CoordinatorRequest::AdminStatus {
        tenant: "tenant".to_owned(),
        actor_user: "admin".to_owned(),
        admin_proof,
        admin_nonce,
        issued_at_epoch_seconds,
    };
    let CoordinatorResponse::AdminStatus {
        tenant,
        actor,
        suspended,
        safe_default,
    } = service
        .handle_request(admin_status_request.clone())
        .unwrap()
    else {
        panic!("expected admin status");
    };
    assert_eq!(tenant, TenantId::from("tenant"));
    assert_eq!(actor, UserId::from("admin"));
    assert!(!suspended);
    assert_eq!(safe_default, "read_only");
    let replayed_admin_status = service.handle_request(admin_status_request).unwrap_err();
    assert!(replayed_admin_status
        .to_string()
        .contains("nonce was already used"));

    let (admin_proof, admin_nonce, issued_at_epoch_seconds) = test_admin_request(
        "admin-token",
        "suspend_tenant",
        "admin-tenant",
        "admin",
        "tenant",
        "admin-suspend-1",
    );
    let CoordinatorResponse::TenantSuspended {
        tenant,
        actor,
        policy,
    } = service
        .handle_request(CoordinatorRequest::SuspendTenant {
            tenant: "admin-tenant".to_owned(),
            actor_user: "admin".to_owned(),
            target_tenant: "tenant".to_owned(),
            admin_proof,
            admin_nonce,
            issued_at_epoch_seconds,
        })
        .unwrap()
    else {
        panic!("expected tenant suspension");
    };
    assert_eq!(tenant, TenantId::from("tenant"));
    assert_eq!(actor, UserId::from("admin"));
    assert_eq!(policy.name, "tenant:suspended");

    let (admin_proof, admin_nonce, issued_at_epoch_seconds) = test_admin_request(
        "admin-token",
        "admin_status",
        "tenant",
        "admin",
        "tenant",
        "admin-status-2",
    );
    let CoordinatorResponse::AdminStatus { suspended, .. } = service
        .handle_request(CoordinatorRequest::AdminStatus {
            tenant: "tenant".to_owned(),
            actor_user: "admin".to_owned(),
            admin_proof,
            admin_nonce,
            issued_at_epoch_seconds,
        })
        .unwrap()
    else {
        panic!("expected suspended admin status");
    };
    assert!(suspended);

    let (admin_proof, admin_nonce, issued_at_epoch_seconds) = test_admin_request(
        "admin-token",
        "admin_status",
        "tenant",
        "admin",
        "tenant",
        "admin-status-unconfigured",
    );
    let missing_admin_credential = CoordinatorService::new(7)
        .handle_request(CoordinatorRequest::AdminStatus {
            tenant: "tenant".to_owned(),
            actor_user: "admin".to_owned(),
            admin_proof,
            admin_nonce,
            issued_at_epoch_seconds,
        })
        .unwrap_err();
    assert!(missing_admin_credential
        .to_string()
        .contains("admin credential is not configured"));

    let (admin_proof, admin_nonce, issued_at_epoch_seconds) = test_admin_request(
        "wrong-token",
        "suspend_tenant",
        "admin-tenant",
        "admin",
        "other-tenant",
        "admin-suspend-wrong",
    );
    let invalid_admin_credential = service
        .handle_request(CoordinatorRequest::SuspendTenant {
            tenant: "admin-tenant".to_owned(),
            actor_user: "admin".to_owned(),
            target_tenant: "other-tenant".to_owned(),
            admin_proof,
            admin_nonce,
            issued_at_epoch_seconds,
        })
        .unwrap_err();
    assert!(invalid_admin_credential
        .to_string()
        .contains("admin request proof is invalid"));

    let CoordinatorResponse::AuthStatus {
        account_status,
        suspended,
        disabled,
        sanitized_reason,
        next_actions,
        sensitive_moderation_details_exposed,
        signup_failure_details_exposed,
        ..
    } = service
        .handle_request(CoordinatorRequest::AuthStatus {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected suspended auth status");
    };
    assert_eq!(account_status, "suspended");
    assert!(suspended);
    assert!(!disabled);
    assert_eq!(
        sanitized_reason.as_deref(),
        Some("account or tenant is suspended by hosted policy")
    );
    assert!(next_actions
        .iter()
        .any(|action| action.contains("hosted operator")));
    assert!(!sensitive_moderation_details_exposed);
    assert!(!signup_failure_details_exposed);

    let create = service
        .handle_request(CoordinatorRequest::CreateProject {
            tenant: "tenant".to_owned(),
            actor_user: "user".to_owned(),
            project: "project".to_owned(),
            name: "Demo".to_owned(),
        })
        .unwrap_err();
    assert!(create.to_string().contains("tenant is suspended"));

    let start = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: Some("attempt-a".to_owned()),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process".to_owned(),
            restart: false,
        })
        .unwrap_err();
    assert!(start.to_string().contains("tenant is suspended"));
}

#[test]
fn service_manages_project_scoped_agent_public_keys() {
    let mut service = CoordinatorService::new(7);

    let CoordinatorResponse::AgentPublicKey { record, actor } = service
        .handle_request(CoordinatorRequest::RegisterAgentPublicKey {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            user: "user".to_owned(),
            agent: "agent-ci".to_owned(),
            public_key: "agent-key-v1".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected agent public key registration");
    };
    assert_eq!(actor, UserId::from("user"));
    assert_eq!(record.tenant, TenantId::from("tenant"));
    assert_eq!(record.project, ProjectId::from("project"));
    assert_eq!(record.user, UserId::from("user"));
    assert_eq!(record.agent, AgentId::from("agent-ci"));
    assert_eq!(record.version, 1);
    assert!(!record.revoked);
    assert_eq!(record.scopes, vec!["project:read", "project:run"]);
    assert!(!record.human_account_creation_privilege);
    assert!(!record.browser_interaction_required_each_run);

    let CoordinatorResponse::AgentPublicKey { record, .. } = service
        .handle_request(CoordinatorRequest::RegisterAgentPublicKey {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            user: "user".to_owned(),
            agent: "agent-ci".to_owned(),
            public_key: "agent-key-v2".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected agent public key rotation by re-add");
    };
    assert_eq!(record.version, 2);
    assert_eq!(record.public_key, "agent-key-v2");

    let CoordinatorResponse::AgentPublicKeys { records, actor } = service
        .handle_request(CoordinatorRequest::ListAgentPublicKeys {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            user: "user".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected agent public key list");
    };
    assert_eq!(actor, UserId::from("user"));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].agent, AgentId::from("agent-ci"));

    let CoordinatorResponse::AgentPublicKeys { records, .. } = service
        .handle_request(CoordinatorRequest::ListAgentPublicKeys {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            user: "other-user".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected foreign user agent public key list");
    };
    assert!(records.is_empty());

    let CoordinatorResponse::AgentPublicKeys { records, .. } = service
        .handle_request(CoordinatorRequest::ListAgentPublicKeys {
            tenant: "other-tenant".to_owned(),
            project: "project".to_owned(),
            user: "user".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected foreign tenant agent public key list");
    };
    assert!(records.is_empty());

    let foreign_user_revoke = service
        .handle_request(CoordinatorRequest::RevokeAgentPublicKey {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            user: "other-user".to_owned(),
            agent: "agent-ci".to_owned(),
        })
        .unwrap_err();
    assert!(foreign_user_revoke
        .to_string()
        .contains("signed-in user scope"));

    let CoordinatorResponse::AgentPublicKey { record, actor } = service
        .handle_request(CoordinatorRequest::RevokeAgentPublicKey {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            user: "user".to_owned(),
            agent: "agent-ci".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected agent public key revocation");
    };
    assert_eq!(actor, UserId::from("user"));
    assert!(record.revoked);
}

#[test]
fn service_runs_agent_workflows_with_scoped_key_attribution() {
    let mut service = CoordinatorService::new(7);
    let agent_public_key = test_agent_public_key();
    let agent_fingerprint = Digest::sha256(&agent_public_key);

    service
        .handle_request(CoordinatorRequest::RegisterAgentPublicKey {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            user: "user".to_owned(),
            agent: "agent-ci".to_owned(),
            public_key: agent_public_key,
        })
        .unwrap();

    let fingerprint_only = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: Some("agent-ci".to_owned()),
            agent_public_key_fingerprint: Some(agent_fingerprint.clone()),
            agent_signature: None,
            process: "vp-agent-fingerprint-only".to_owned(),
            restart: false,
        })
        .unwrap_err();
    assert!(fingerprint_only.to_string().contains("signed request"));

    let wrong_fingerprint = service
        .handle_request(with_signed_agent_workflow(
            CoordinatorRequest::StartProcess {
                launch_attempt: None,
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                actor_user: None,
                actor_agent: Some("agent-ci".to_owned()),
                agent_public_key_fingerprint: Some(Digest::sha256("other-key")),
                agent_signature: None,
                process: "vp-agent-bad-key".to_owned(),
                restart: false,
            },
            "start_process",
            "vp-agent-bad-key",
            None,
            "bad-fingerprint-nonce",
        ))
        .unwrap_err();
    assert!(wrong_fingerprint.to_string().contains("fingerprint"));

    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "worker-linux".to_owned(),
            public_key: test_node_public_key("worker-linux"),
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "worker-linux".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap();

    let CoordinatorResponse::ProcessStarted {
        launch_attempt: None,
        actor: start_actor,
        ..
    } = service
        .handle_request(with_signed_agent_workflow(
            CoordinatorRequest::StartProcess {
                launch_attempt: None,
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                actor_user: None,
                actor_agent: Some("agent-ci".to_owned()),
                agent_public_key_fingerprint: Some(agent_fingerprint.clone()),
                agent_signature: None,
                process: "vp-agent".to_owned(),
                restart: false,
            },
            "start_process",
            "vp-agent",
            None,
            "start-nonce",
        ))
        .unwrap()
    else {
        panic!("expected agent-authenticated process start");
    };
    assert_agent_workflow_actor(&start_actor, &agent_fingerprint);

    let replay = service
        .handle_request(with_signed_agent_workflow(
            CoordinatorRequest::StartProcess {
                launch_attempt: None,
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                actor_user: None,
                actor_agent: Some("agent-ci".to_owned()),
                agent_public_key_fingerprint: Some(agent_fingerprint.clone()),
                agent_signature: None,
                process: "vp-agent".to_owned(),
                restart: true,
            },
            "start_process",
            "vp-agent",
            None,
            "start-nonce",
        ))
        .unwrap_err();
    assert!(replay.to_string().contains("nonce"));

    let denied_external_task = service
        .handle_request(with_signed_agent_workflow(
            CoordinatorRequest::LaunchTask {
                task_spec: test_task_spec(
                    "tenant",
                    "project",
                    "vp-agent",
                    "compile-linux",
                    7,
                    [Capability::Command],
                ),
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                actor_user: None,
                actor_agent: Some("agent-ci".to_owned()),
                agent_public_key_fingerprint: Some(agent_fingerprint.clone()),
                agent_signature: None,
                wait_for_node: false,
                artifact_path: "/vfs/artifacts/dap-output.txt".to_owned(),
                wasm_module_base64: test_wasm_module_base64(),
            },
            "launch_task",
            "vp-agent",
            Some("compile-linux"),
            "launch-nonce",
        ))
        .unwrap_err();
    assert!(denied_external_task
        .to_string()
        .contains("external callers may launch only EntrypointV1"));
}

#[test]
fn signed_node_and_agent_requests_reject_body_modification() {
    let mut service = CoordinatorService::new(7);
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "worker-bound-body".to_owned(),
            public_key: test_node_public_key("worker-bound-body"),
        })
        .unwrap();

    let original_node_request = CoordinatorRequest::ReportNodeCapabilities {
        tenant: "tenant".to_owned(),
        project: "project".to_owned(),
        node: "worker-bound-body".to_owned(),
        capabilities: linux_capabilities(),
        cached_environment_digests: Vec::new(),
        dependency_cache_digests: Vec::new(),
        source_snapshots: Vec::new(),
        artifact_locations: Vec::new(),
        online: true,
    };
    let original_node_digest =
        signed_request_payload_digest(&serde_json::to_value(&original_node_request).unwrap());
    let node_signature = signed_node_request_with_private_key(
        "worker-bound-body",
        &test_node_private_key("worker-bound-body"),
        "report_node_capabilities",
        &original_node_digest,
        "node-body-modification",
    );
    let mut modified_node_request = original_node_request;
    let CoordinatorRequest::ReportNodeCapabilities { online, .. } = &mut modified_node_request
    else {
        unreachable!();
    };
    *online = false;
    let modified_node = service
        .handle_request(CoordinatorRequest::SignedNode {
            node: "worker-bound-body".to_owned(),
            node_signature,
            request: Box::new(modified_node_request),
        })
        .unwrap_err();
    assert!(modified_node.to_string().contains("signature"));

    let agent_public_key = test_agent_public_key();
    let agent_fingerprint = Digest::sha256(&agent_public_key);
    service
        .handle_request(CoordinatorRequest::RegisterAgentPublicKey {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            user: "user".to_owned(),
            agent: "agent-ci".to_owned(),
            public_key: agent_public_key,
        })
        .unwrap();
    let original_agent_request = CoordinatorRequest::StartProcess {
        launch_attempt: None,
        tenant: "tenant".to_owned(),
        project: "project".to_owned(),
        actor_user: None,
        actor_agent: Some("agent-ci".to_owned()),
        agent_public_key_fingerprint: Some(agent_fingerprint),
        agent_signature: None,
        process: "vp-agent-bound-body".to_owned(),
        restart: false,
    };
    let agent_signature = signed_agent_workflow_request(
        &original_agent_request,
        "start_process",
        "vp-agent-bound-body",
        None,
        "agent-body-modification",
    );
    let mut modified_agent_request = original_agent_request;
    let CoordinatorRequest::StartProcess {
        launch_attempt: None,
        restart,
        agent_signature: request_signature,
        ..
    } = &mut modified_agent_request
    else {
        unreachable!();
    };
    *restart = true;
    *request_signature = Some(agent_signature);
    let modified_agent = service.handle_request(modified_agent_request).unwrap_err();
    assert!(modified_agent.to_string().contains("signature"));
}

#[test]
fn service_checks_spawn_quota_before_process_or_task_work_starts() {
    let mut service = CoordinatorService::new(7);
    service.quota.set_workflow_limits(ResourceLimits {
        limits: BTreeMap::from([(LimitKind::Spawn, 2)]),
    });

    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "worker-linux".to_owned(),
            public_key: test_node_public_key("worker-linux"),
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "worker-linux".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap();

    let CoordinatorResponse::ProcessStarted {
        launch_attempt: None,
        charged_spawns,
        ..
    } = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "vp-quota".to_owned(),
            restart: false,
        })
        .unwrap()
    else {
        panic!("expected process start within spawn quota");
    };
    assert_eq!(charged_spawns, 1);

    let CoordinatorResponse::TaskLaunched { charged_spawns, .. } = service
        .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
            task_spec: test_task_spec(
                "tenant",
                "project",
                "vp-quota",
                "compile-linux",
                7,
                [Capability::Command],
            ),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: Some("user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            wait_for_node: false,
            artifact_path: "/vfs/artifacts/dap-output.txt".to_owned(),
            wasm_module_base64: test_wasm_module_base64(),
        })
        .unwrap()
    else {
        panic!("expected task launch within spawn quota");
    };
    assert_eq!(charged_spawns, 2);

    let denied_task = service
        .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
            task_spec: test_task_spec(
                "tenant",
                "project",
                "vp-quota",
                "compile-linux-denied",
                7,
                [Capability::Command],
            ),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: Some("user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            wait_for_node: false,
            artifact_path: "/vfs/artifacts/denied.txt".to_owned(),
            wasm_module_base64: test_wasm_module_base64(),
        })
        .unwrap_err();
    assert!(denied_task.to_string().contains("Spawn"));
    let now_epoch_seconds = service.current_epoch_seconds().unwrap();
    assert_eq!(
        service.quota.used_workflow_spawns(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            now_epoch_seconds,
        ),
        2
    );

    let denied_task_key = task_control_key(
        &TenantId::from("tenant"),
        &ProjectId::from("project"),
        &ProcessId::from("vp-quota"),
        &NodeId::from("worker-linux"),
        &TaskInstanceId::from("compile-linux-denied"),
    );
    assert!(!service.task_registry.is_active(&denied_task_key));
    assert!(service.task_registry.placement(&denied_task_key).is_none());
    assert_eq!(
        service
            .task_registry
            .assignments_for_node(&(
                TenantId::from("tenant"),
                ProjectId::from("project"),
                NodeId::from("worker-linux"),
            ))
            .count(),
        1
    );

    let other_project_process = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "other-project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "vp-denied".to_owned(),
            restart: false,
        })
        .unwrap();
    assert!(matches!(
        other_project_process,
        CoordinatorResponse::ProcessStarted {
            launch_attempt: None,
            ..
        }
    ));
    assert_eq!(
        service.quota.used_workflow_spawns(
            &TenantId::from("tenant"),
            &ProjectId::from("other-project"),
            now_epoch_seconds,
        ),
        1
    );
    assert_eq!(
        service.quota.used_workflow_spawns(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            now_epoch_seconds,
        ),
        2
    );
}

#[test]
fn project_quota_resets_at_the_configured_window_boundary() {
    let mut limits = ResourceLimits::unlimited();
    limits.limits.insert(LimitKind::Spawn, 1);
    let quota = CoordinatorQuotaConfiguration::new(limits, [(LimitKind::Spawn, 60)]).unwrap();
    let mut service = CoordinatorService::new_with_admin_token_database_url_and_quota(
        7,
        "test-admin-token",
        None,
        quota,
    )
    .unwrap();

    service.set_server_time(59);
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: Some("attempt-b".to_owned()),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "vp-window-one".to_owned(),
            restart: false,
        })
        .unwrap();
    service
        .handle_request(CoordinatorRequest::AbortProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "vp-window-one".to_owned(),
        })
        .unwrap();

    let exhausted = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: Some("attempt-b".to_owned()),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "vp-still-window-one".to_owned(),
            restart: false,
        })
        .unwrap_err();
    assert!(exhausted.to_string().contains("Spawn"));

    service.set_server_time(60);
    let started = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "vp-window-two".to_owned(),
            restart: false,
        })
        .unwrap();
    assert!(matches!(
        started,
        CoordinatorResponse::ProcessStarted {
            launch_attempt: None,
            charged_spawns: 1,
            ..
        }
    ));
    assert_eq!(service.quota.active_meter_count(), 1);
}

#[test]
fn authenticated_api_calls_are_metered_per_tenant_and_project_before_dispatch() {
    let mut limits = ResourceLimits::unlimited();
    limits.limits.insert(LimitKind::ApiCall, 1);
    let quota = CoordinatorQuotaConfiguration::new(limits, [(LimitKind::ApiCall, 60)]).unwrap();
    let mut service = CoordinatorService::new_with_admin_token_database_url_and_quota(
        7,
        "test-admin-token",
        None,
        quota,
    )
    .unwrap();
    service.set_server_time(30);
    for (project, secret) in [("project-a", "session-a"), ("project-b", "session-b")] {
        service
            .issue_cli_session(
                TenantId::from("tenant"),
                ProjectId::from(project),
                UserId::from("user"),
                secret,
                None,
            )
            .unwrap();
    }

    service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::AuthStatus,
        })
        .unwrap();
    let denied = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::AuthStatus,
        })
        .unwrap_err();
    assert!(denied.to_string().contains("ApiCall"));

    service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-b".to_owned(),
            request: AuthenticatedCoordinatorRequest::AuthStatus,
        })
        .unwrap();
    assert_eq!(
        service
            .quota
            .used_api_calls(&TenantId::from("tenant"), &ProjectId::from("project-a"), 30,),
        1
    );
    assert_eq!(
        service
            .quota
            .used_api_calls(&TenantId::from("tenant"), &ProjectId::from("project-b"), 30,),
        1
    );
}

#[test]
fn hosted_quota_overrides_are_partial_tenant_scoped_effective_and_clear_immediately() {
    let quota = CoordinatorQuotaConfiguration::unlimited().with_admission_limits(1, 4, 1);
    let mut service = CoordinatorService::new_with_admin_token_database_url_and_quota(
        7,
        "admin-token",
        None,
        quota,
    )
    .unwrap();
    let tenant_a = TenantId::from("tenant-a");
    let tenant_b = TenantId::from("tenant-b");
    let operator = UserId::from("hosted-admin");

    service
        .configure_hosted_tenant_quota(
            tenant_a.clone(),
            Some(TenantQuotaOverrideValues {
                max_projects: Some(2),
                max_nodes: None,
                max_active_processes: None,
            }),
            operator.clone(),
            "quota_set",
            10,
            1_000_000,
        )
        .unwrap();
    for project in ["a-one", "a-two"] {
        service
            .handle_request(CoordinatorRequest::CreateProject {
                tenant: tenant_a.to_string(),
                actor_user: "user-a".to_owned(),
                project: project.to_owned(),
                name: project.to_owned(),
            })
            .unwrap();
    }
    let third = service
        .handle_request(CoordinatorRequest::CreateProject {
            tenant: tenant_a.to_string(),
            actor_user: "user-a".to_owned(),
            project: "a-three".to_owned(),
            name: "A three".to_owned(),
        })
        .unwrap_err();
    assert!(third
        .to_string()
        .contains("project quota exceeded (2 of 2)"));
    let project_quota_error = third.api_error("quota-project");
    assert_eq!(project_quota_error.code, ApiErrorCode::QuotaExceeded);
    assert_eq!(project_quota_error.resource.as_deref(), Some("project"));
    assert_eq!(project_quota_error.current, Some(2));
    assert_eq!(project_quota_error.maximum, Some(2));

    service
        .handle_request(CoordinatorRequest::CreateProject {
            tenant: tenant_b.to_string(),
            actor_user: "user-b".to_owned(),
            project: "b-one".to_owned(),
            name: "B one".to_owned(),
        })
        .unwrap();
    let tenant_b_second = service
        .handle_request(CoordinatorRequest::CreateProject {
            tenant: tenant_b.to_string(),
            actor_user: "user-b".to_owned(),
            project: "b-two".to_owned(),
            name: "B two".to_owned(),
        })
        .unwrap_err();
    assert!(tenant_b_second
        .to_string()
        .contains("project quota exceeded (1 of 1)"));

    let CoordinatorResponse::QuotaStatus {
        projects_current,
        projects_maximum,
        node_identities_maximum,
        active_processes_maximum,
        ..
    } = service
        .handle_request(CoordinatorRequest::QuotaStatus {
            tenant: tenant_a.to_string(),
            project: "a-one".to_owned(),
            actor_user: "user-a".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected quota status");
    };
    assert_eq!(projects_current, 2);
    assert_eq!(projects_maximum, 2);
    assert_eq!(node_identities_maximum, 4);
    assert_eq!(active_processes_maximum, 1);

    service
        .configure_hosted_tenant_quota(
            tenant_a.clone(),
            None,
            operator,
            "quota_clear",
            11,
            1_000_000,
        )
        .unwrap();
    let status = service.hosted_tenant_admin_status(&tenant_a);
    assert!(status.quota_override.is_none());
    assert_eq!(status.effective_quota.max_projects, 1);
    assert_eq!(status.projects_current, 2);
    let admission_after_lowering = service
        .handle_request(CoordinatorRequest::CreateProject {
            tenant: tenant_a.to_string(),
            actor_user: "user-a".to_owned(),
            project: "a-after-clear".to_owned(),
            name: "A after clear".to_owned(),
        })
        .unwrap_err();
    assert!(admission_after_lowering
        .to_string()
        .contains("project quota exceeded (2 of 1)"));
    assert_eq!(service.coordinator.durable.hosted_admin.audit.len(), 2);
    let set_audit = &service.coordinator.durable.hosted_admin.audit[0];
    assert_eq!(set_audit.action, "quota_set");
    assert!(set_audit.old_quota_override.is_none());
    assert_eq!(
        set_audit
            .new_quota_override
            .as_ref()
            .and_then(|values| values.max_projects),
        Some(2)
    );
    let clear_audit = &service.coordinator.durable.hosted_admin.audit[1];
    assert_eq!(clear_audit.action, "quota_clear");
    assert!(clear_audit.new_quota_override.is_none());
    assert_eq!(clear_audit.operator, UserId::from("hosted-admin"));
    assert_eq!(clear_audit.occurred_at_epoch_seconds, 11);
}

#[test]
fn hosted_account_suspend_revokes_sessions_aborts_execution_preserves_data_and_resumes_fresh() {
    let mut service = CoordinatorService::new_with_admin_token(7, "admin-token");
    let tenant = TenantId::from("tenant");
    let other_tenant = TenantId::from("other-tenant");
    let project = ProjectId::from("project");
    let process = ProcessId::from("process");
    service
        .issue_cli_session(
            tenant.clone(),
            project.clone(),
            UserId::from("user"),
            "tenant-session",
            None,
        )
        .unwrap();
    service
        .issue_cli_session(
            other_tenant.clone(),
            ProjectId::from("other-project"),
            UserId::from("other-user"),
            "other-session",
            None,
        )
        .unwrap();
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: tenant.to_string(),
            project: project.to_string(),
            node: "node".to_owned(),
            public_key: test_node_public_key("hosted-account-node"),
        })
        .unwrap();
    service
        .coordinator
        .start_process(tenant.clone(), project.clone(), process);

    let suspended = service
        .suspend_hosted_account(tenant.clone(), UserId::from("hosted-admin"), 20)
        .unwrap();
    assert_eq!(suspended.status.account.account_status, "suspended");
    assert_eq!(suspended.revoked_sessions, 1);
    assert_eq!(suspended.aborted_processes, 1);
    assert_eq!(suspended.status.active_processes_current, 0);
    assert!(service.coordinator.project(&project).is_some());
    assert!(service
        .coordinator
        .node_identity(&tenant, &project, &NodeId::from("node"))
        .is_some());
    assert!(service
        .authenticate_cli_session_status_context("tenant-session")
        .unwrap_err()
        .to_string()
        .contains("revoked"));
    service
        .authenticate_cli_session_context("other-session")
        .expect("suspending one tenant must not revoke another tenant's session");

    let repeated = service
        .suspend_hosted_account(tenant.clone(), UserId::from("hosted-admin"), 21)
        .unwrap();
    assert_eq!(repeated.revoked_sessions, 0);
    assert_eq!(repeated.aborted_processes, 0);

    let resumed = service
        .resume_hosted_account(tenant.clone(), UserId::from("hosted-admin"), 22)
        .unwrap();
    assert_eq!(resumed.status.account.account_status, "active");
    assert!(service
        .authenticate_cli_session_status_context("tenant-session")
        .unwrap_err()
        .to_string()
        .contains("revoked"));
    service
        .issue_cli_session(tenant, project, UserId::from("user"), "fresh-session", None)
        .expect("resumed account may create a fresh session");
}

#[test]
fn signed_node_log_ingestion_truncates_at_scoped_quota_without_failing_reports() {
    let mut limits = ResourceLimits::unlimited();
    limits.limits.insert(LimitKind::LogBytes, 4);
    let quota = CoordinatorQuotaConfiguration::new(limits, [(LimitKind::LogBytes, 60)]).unwrap();
    let mut service = CoordinatorService::new_with_admin_token_database_url_and_quota(
        7,
        "test-admin-token",
        None,
        quota,
    )
    .unwrap();
    service.set_server_time(30);
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            public_key: test_node_public_key("node"),
        })
        .unwrap();
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process".to_owned(),
            restart: false,
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReconnectNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            process: "process".to_owned(),
            epoch: 7,
        })
        .unwrap();
    register_test_task_assignment(
        &mut service,
        "tenant",
        "project",
        "process",
        "node",
        "task",
        "task",
        7,
    );

    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportTaskLog {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node".to_owned(),
            task: "task".to_owned(),
            stdout_bytes: 3,
            stderr_bytes: 1,
            stdout_tail: "out".to_owned(),
            stderr_tail: "e".to_owned(),
            stdout_truncated: false,
            stderr_truncated: false,
            backpressured: false,
        })
        .unwrap();
    let truncated = service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportTaskLog {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node".to_owned(),
            task: "task".to_owned(),
            stdout_bytes: 4,
            stderr_bytes: 1,
            stdout_tail: "outx".to_owned(),
            stderr_tail: "e".to_owned(),
            stdout_truncated: false,
            stderr_truncated: false,
            backpressured: true,
        })
        .unwrap();
    let CoordinatorResponse::TaskLogRecorded {
        stdout_tail,
        stdout_bytes: 4,
        ..
    } = truncated
    else {
        panic!("expected a successful truncated task-log report");
    };
    assert_eq!(stdout_tail, "[log output truncated at project log quota]");
    assert!(service
        .recent_log_store
        .entries_for_project(&TenantId::from("tenant"), &ProjectId::from("project"))
        .iter()
        .any(|entry| entry.text.contains("project log quota") && entry.truncated));
    assert_eq!(
        service
            .quota
            .used_log_bytes(&TenantId::from("tenant"), &ProjectId::from("project"), 30,),
        4
    );
}

#[test]
fn log_quota_exhaustion_cannot_strand_task_completion_or_artifact_publication() {
    let mut limits = ResourceLimits::unlimited();
    limits.limits.insert(LimitKind::LogBytes, 4);
    let quota = CoordinatorQuotaConfiguration::new(limits, [(LimitKind::LogBytes, 60)]).unwrap();
    let mut service = CoordinatorService::new_with_admin_token_database_url_and_quota(
        7,
        "test-admin-token",
        None,
        quota,
    )
    .unwrap();
    service.set_server_time(30);
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            public_key: test_node_public_key("node"),
        })
        .unwrap();
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process".to_owned(),
            restart: false,
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReconnectNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            process: "process".to_owned(),
            epoch: 7,
        })
        .unwrap();
    register_test_task_assignment(
        &mut service,
        "tenant",
        "project",
        "process",
        "node",
        "compile",
        "compile-one",
        7,
    );
    service.record_task_completion_event(TaskCompletionEvent {
        tenant: TenantId::from("tenant"),
        project: ProjectId::from("project"),
        process: ProcessId::from("process"),
        node: NodeId::from("coordinator-main"),
        executor: TaskExecutor::CoordinatorMain,
        task_definition: TaskDefinitionId::from("build"),
        task: TaskInstanceId::from("main"),
        attempt_id: None,
        placement: None,
        terminal_state: TaskTerminalState::Completed,
        status_code: Some(0),
        stdout_bytes: 0,
        stderr_bytes: 0,
        stdout_tail: String::new(),
        stderr_tail: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        artifact_path: None,
        artifact_digest: None,
        artifact_size_bytes: None,
        result: None,
    });

    service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node".to_owned(),
            task: "compile-one".to_owned(),
            terminal_state: Some(TaskTerminalState::Completed),
            status_code: Some(0),
            stdout_bytes: 64,
            stderr_bytes: 0,
            stdout_tail: "the-real-final-tail".to_owned(),
            stderr_tail: String::new(),
            stdout_truncated: true,
            stderr_truncated: false,
            artifact_path: Some("/vfs/artifacts/result.bin".to_owned()),
            artifact_digest: Some(Digest::sha256("artifact bytes")),
            artifact_size_bytes: Some(14),
            result: None,
        })
        .unwrap();

    let event = service
        .task_registry
        .events()
        .find(|event| event.task == TaskInstanceId::from("compile-one"))
        .unwrap();
    assert_eq!(
        event.stdout_tail,
        "[log output truncated at project log quota]"
    );
    assert!(event.stdout_truncated);
    assert!(!service
        .task_registry
        .active_tasks()
        .any(|key| key.4 == TaskInstanceId::from("compile-one")));
    assert!(service
        .coordinator
        .active_process(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &ProcessId::from("process"),
        )
        .is_none());
    assert!(matches!(
        service
            .handle_request(CoordinatorRequest::GetArtifact {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                actor_user: "user".to_owned(),
                artifact: "result.bin".to_owned(),
            })
            .unwrap(),
        CoordinatorResponse::Artifact { .. }
    ));
}
