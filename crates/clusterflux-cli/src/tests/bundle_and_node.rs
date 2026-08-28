use super::*;

#[test]
fn bundle_inspect_discovers_environments_selected_inputs_and_source_providers() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("envs/linux")).unwrap();
    fs::create_dir_all(temp.path().join("envs/docker")).unwrap();
    fs::write(
        temp.path().join("envs/linux/Containerfile"),
        "FROM alpine\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("envs/docker/Dockerfile"),
        "FROM debian:stable-slim\n",
    )
    .unwrap();
    write_constrained_workflow(
        temp.path(),
        "demo",
        "fn main() {}\n\n#[clusterflux::task]\nfn compile_linux() {}\n\n#[clusterflux::main]\nfn build_main() {}\n",
    );

    let Cli {
        command: Commands::Bundle {
            command: BundleCommands::Inspect(args),
        },
    } = parse(&[
        "clusterflux",
        "bundle",
        "inspect",
        "--project",
        temp.path().to_str().unwrap(),
    ])
    else {
        panic!("wrong command");
    };
    let inspection = bundle_inspection(args, PathBuf::from("/unused")).unwrap();

    assert_eq!(inspection.project, temp.path());
    assert!(inspection
        .default_source_providers
        .contains(&SourceProviderKind::Git));
    assert!(inspection.source_provider_statuses.iter().any(|status| {
        status.provider == "filesystem" && status.status == "enabled" && status.active
    }));
    assert!(inspection
        .source_provider_statuses
        .iter()
        .any(|status| status.provider == "git" && status.status == "missing"));
    assert!(inspection
        .source_provider_manifest
        .description
        .contains("node task"));
    assert!(
        !inspection
            .source_provider_manifest
            .coordinator_requires_checkout_access
    );
    assert!(
        !inspection
            .source_provider_manifest
            .transfer_policy
            .default_full_repo_tarball
    );
    assert!(inspection
        .metadata
        .environments
        .iter()
        .any(|environment| environment.name == "linux"));
    assert!(inspection
        .metadata
        .environments
        .iter()
        .any(|environment| environment.name == "docker"));
    assert_eq!(
        inspection.metadata.source_metadata.source_provider_manifest,
        inspection.source_provider_manifest.digest
    );
    assert!(
        inspection
            .metadata
            .source_metadata
            .transfer_policy
            .local_source_bytes_remain_node_local
    );
    assert!(
        !inspection
            .metadata
            .source_metadata
            .transfer_policy
            .coordinator_receives_source_bytes_by_default
    );
    assert!(
        !inspection
            .metadata
            .source_metadata
            .transfer_policy
            .default_full_repo_tarball
    );
    assert!(inspection
        .metadata
        .task_metadata
        .entrypoints
        .contains(&"build".to_owned()));
    assert_eq!(
        inspection.metadata.task_metadata.default_entrypoint,
        "build"
    );
    assert_eq!(
        inspection.metadata.task_metadata.task_abi,
        task_abi_digest(&ProjectModel::discover_without_config(temp.path()).unwrap())
    );
    assert!(inspection
        .metadata
        .wasm_code
        .as_str()
        .starts_with("sha256:"));
    assert!(inspection.metadata.debug_metadata.available);
    assert!(inspection.metadata.debug_metadata.source_level_breakpoints);
    assert!(inspection.metadata.debug_metadata.variables_pane_supported);
    assert!(inspection
        .metadata
        .debug_metadata
        .probes
        .iter()
        .any(|probe| probe.source_path == ".clusterflux/main.rs"
            && probe.function == "compile_linux"
            && probe.task.as_str() == "compile_linux"));
    assert!(
        inspection
            .metadata
            .large_input_policy
            .selected_inputs_are_content_digests
    );
    assert!(
        !inspection
            .metadata
            .large_input_policy
            .selected_input_bytes_included
    );
    assert!(
        !inspection
            .metadata
            .large_input_policy
            .full_repository_bytes_included
    );
    assert!(
        !inspection
            .metadata
            .large_input_policy
            .silent_task_argument_serialization
    );
    assert!(inspection
        .metadata
        .large_input_policy
        .supported_handle_types
        .contains(&"SourceSnapshot".to_owned()));
    assert!(
        inspection
            .metadata
            .restart_compatibility
            .source_edits_can_restart_from_clean_task_boundary
    );
    assert!(
        inspection
            .metadata
            .restart_compatibility
            .requires_clean_checkpoint_boundary
    );
    assert_eq!(
        inspection.metadata.restart_compatibility.compares_task_abi,
        inspection.metadata.task_metadata.task_abi
    );
    assert!(
        inspection
            .metadata
            .restart_compatibility
            .incompatible_changes_require_whole_process_restart
    );
    assert!(!inspection.metadata.embeds_full_container_images);
    assert!(inspection
        .metadata
        .selected_inputs
        .iter()
        .any(|input| input.path == ".clusterflux/Cargo.toml"));
    assert!(inspection
        .metadata
        .selected_inputs
        .iter()
        .any(|input| input.path == ".clusterflux/main.rs"));
    assert!(inspection.environment_diagnostics.is_empty());
    assert!(inspection
        .pre_schedule_diagnostics
        .iter()
        .any(|diagnostic| diagnostic.category == "capability"
            && diagnostic.message.contains("environment `linux`")));
}

#[test]
fn bundle_inspect_reports_missing_environment_references_before_schedule() {
    let temp = tempfile::tempdir().unwrap();
    write_constrained_workflow(
        temp.path(),
        "demo",
        "fn main() { let _target = env!(\"linux\"); }\n",
    );

    let inspection = bundle_inspection(
        BundleInspectArgs {
            project: Some(temp.path().to_path_buf()),
            source_provider: None,
            disabled_source_providers: Vec::new(),
            json: false,
        },
        PathBuf::from("/unused"),
    )
    .unwrap();

    assert_eq!(inspection.environment_diagnostics.len(), 1);
    assert_eq!(
        inspection.environment_diagnostics[0].path,
        ".clusterflux/main.rs"
    );
    assert_eq!(
        inspection.environment_diagnostics[0].reference.name,
        "linux"
    );
    assert!(inspection.environment_diagnostics[0]
        .message
        .contains("missing Clusterflux environment `linux`"));
    assert!(inspection
        .pre_schedule_diagnostics
        .iter()
        .any(|diagnostic| {
            diagnostic.severity == "error"
                && diagnostic.category == "environment"
                && diagnostic.code == "missing_environment"
        }));
}

#[test]
fn bundle_inspect_reports_source_provider_overrides_before_schedule() {
    let temp = tempfile::tempdir().unwrap();
    write_constrained_workflow(temp.path(), "demo", "fn main() {}\n");

    let missing_git = bundle_inspection(
        BundleInspectArgs {
            project: Some(temp.path().to_path_buf()),
            source_provider: Some("git".to_owned()),
            disabled_source_providers: Vec::new(),
            json: false,
        },
        PathBuf::from("/unused"),
    )
    .unwrap();
    assert!(missing_git
        .source_provider_statuses
        .iter()
        .any(|status| { status.provider == "git" && status.status == "missing" && status.active }));
    assert!(missing_git
        .pre_schedule_diagnostics
        .iter()
        .any(|diagnostic| {
            diagnostic.category == "source_provider" && diagnostic.code == "source_provider_missing"
        }));

    let unsupported = bundle_inspection(
        BundleInspectArgs {
            project: Some(temp.path().to_path_buf()),
            source_provider: Some("custom-lfs".to_owned()),
            disabled_source_providers: Vec::new(),
            json: false,
        },
        PathBuf::from("/unused"),
    )
    .unwrap();
    assert!(unsupported.source_provider_statuses.iter().any(|status| {
        status.provider == "custom-lfs" && status.status == "unsupported" && status.active
    }));
    assert!(unsupported
        .pre_schedule_diagnostics
        .iter()
        .any(|diagnostic| {
            diagnostic.category == "source_provider"
                && diagnostic.code == "source_provider_unsupported"
        }));
}

#[test]
fn bundle_identity_changes_when_selected_input_file_changes() {
    let temp = tempfile::tempdir().unwrap();
    write_constrained_workflow(temp.path(), "demo", "fn main() {}\n");

    let first = bundle_inspection(
        BundleInspectArgs {
            project: Some(temp.path().to_path_buf()),
            source_provider: None,
            disabled_source_providers: Vec::new(),
            json: false,
        },
        PathBuf::from("/unused"),
    )
    .unwrap();
    write_constrained_workflow(temp.path(), "changed", "fn main() {}\n");
    let second = bundle_inspection(
        BundleInspectArgs {
            project: Some(temp.path().to_path_buf()),
            source_provider: None,
            disabled_source_providers: Vec::new(),
            json: false,
        },
        PathBuf::from("/unused"),
    )
    .unwrap();

    assert_ne!(first.metadata.identity, second.metadata.identity);
}

#[test]
fn bundle_rebuild_after_source_edit_keeps_restart_compatibility_contract() {
    let temp = tempfile::tempdir().unwrap();
    write_constrained_workflow(temp.path(), "demo", "fn main() { println!(\"first\"); }\n");

    let inspect = |project: &Path| {
        bundle_inspection(
            BundleInspectArgs {
                project: Some(project.to_path_buf()),
                source_provider: None,
                disabled_source_providers: Vec::new(),
                json: true,
            },
            PathBuf::from("/unused"),
        )
        .unwrap()
    };

    let first = inspect(temp.path());
    fs::write(
        temp.path().join(".clusterflux/main.rs"),
        "fn main() { println!(\"second\"); }\n",
    )
    .unwrap();
    let rebuilt = inspect(temp.path());

    assert_ne!(first.metadata.identity, rebuilt.metadata.identity);
    assert_ne!(
        first
            .metadata
            .source_metadata
            .selected_inputs
            .iter()
            .find(|input| input.path == ".clusterflux/main.rs")
            .unwrap()
            .digest,
        rebuilt
            .metadata
            .source_metadata
            .selected_inputs
            .iter()
            .find(|input| input.path == ".clusterflux/main.rs")
            .unwrap()
            .digest
    );
    assert_eq!(
        first.metadata.task_metadata.task_abi,
        rebuilt.metadata.task_metadata.task_abi
    );
    assert_eq!(
        first.metadata.restart_compatibility.compares_task_abi,
        rebuilt.metadata.restart_compatibility.compares_task_abi
    );
    assert!(
        rebuilt
            .metadata
            .restart_compatibility
            .source_edits_can_restart_from_clean_task_boundary
    );
    assert!(
        rebuilt
            .metadata
            .restart_compatibility
            .requires_clean_checkpoint_boundary
    );
    assert!(
        rebuilt
            .metadata
            .restart_compatibility
            .discards_unflushed_task_local_changes
    );
    assert!(
        rebuilt
            .metadata
            .restart_compatibility
            .incompatible_changes_require_whole_process_restart
    );
}

#[test]
fn source_provider_manifest_digest_does_not_include_local_project_path() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    write_constrained_workflow(first.path(), "demo", "fn main() {}\n");
    write_constrained_workflow(second.path(), "demo", "fn main() {}\n");

    let first = bundle_inspection(
        BundleInspectArgs {
            project: Some(first.path().to_path_buf()),
            source_provider: None,
            disabled_source_providers: Vec::new(),
            json: false,
        },
        PathBuf::from("/unused"),
    )
    .unwrap();
    let second = bundle_inspection(
        BundleInspectArgs {
            project: Some(second.path().to_path_buf()),
            source_provider: None,
            disabled_source_providers: Vec::new(),
            json: false,
        },
        PathBuf::from("/unused"),
    )
    .unwrap();

    assert_eq!(
        first.source_provider_manifest.digest,
        second.source_provider_manifest.digest
    );
}

#[test]
fn node_attach_can_exchange_enrollment_grant() {
    let Cli {
        command: Commands::Node {
            command: NodeCommands::Attach(args),
        },
    } = parse(&[
        "clusterflux",
        "node",
        "attach",
        "--enrollment-grant",
        "grant",
        "--public-key",
        "node-key",
    ])
    else {
        panic!("wrong command");
    };
    let plan = attach_plan(args);

    assert!(
        plan.enrollment
            .unwrap()
            .exchanges_short_lived_grant_for_long_lived_node_identity
    );
}

#[test]
fn node_attach_enrollment_uses_default_public_key_when_not_explicit() {
    let Cli {
        command: Commands::Node {
            command: NodeCommands::Attach(args),
        },
    } = parse(&[
        "clusterflux",
        "node",
        "attach",
        "--node",
        "node-default-key",
        "--enrollment-grant",
        "grant",
    ])
    else {
        panic!("wrong command");
    };
    let plan = attach_plan(args);

    let enrollment = plan.enrollment.unwrap();
    assert_eq!(enrollment.grant, "grant");
    assert!(enrollment
        .public_key_fingerprint
        .as_str()
        .starts_with("sha256:"));
}

#[test]
fn node_attach_local_credential_is_durable_and_project_scoped() {
    let temp = tempfile::tempdir().unwrap();
    let node = "node/durable";

    let first = node::load_or_create_local_node_credential(temp.path(), node).unwrap();
    let second = node::load_or_create_local_node_credential(temp.path(), node).unwrap();
    let credential_file = node::local_node_credential_file(temp.path(), node);

    assert_eq!(first, second);
    assert!(credential_file.exists());
    assert!(
        credential_file
            .strip_prefix(temp.path().join(".clusterflux-state").join("nodes"))
            .unwrap()
            .components()
            .count()
            == 1
    );
    let public_key = clusterflux_core::node_ed25519_public_key_from_private_key(&first).unwrap();
    let bytes = fs::read(credential_file).unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(stored["kind"], "clusterflux_node_credential");
    assert_eq!(stored["node"], node);
    assert_eq!(stored["public_key"], public_key);
    assert_eq!(stored["credential_scope"], "local_project_node_identity");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_mode = fs::metadata(node::local_node_credential_file(temp.path(), node))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let directory_mode = fs::metadata(temp.path().join(".clusterflux-state").join("nodes"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(directory_mode, 0o700);
    }
}

#[test]
fn node_attach_rejects_an_explicit_tenant_outside_the_authenticated_scope() {
    let temp = tempfile::tempdir().unwrap();
    write_cli_session(
        temp.path(),
        &StoredCliSession {
            kind: "human".to_owned(),
            coordinator: "127.0.0.1:1".to_owned(),
            tenant: "tenant-authenticated".to_owned(),
            project: "project-authenticated".to_owned(),
            user: "user-authenticated".to_owned(),
            cli_session_credential_kind: "CliDeviceSession".to_owned(),
            session_secret: Some("session-secret".to_owned()),
            token_expiry_posture: "unknown_coordinator_session".to_owned(),
            expires_at: None,
            provider_tokens_exposed_to_cli: false,
            provider_tokens_sent_to_nodes: false,
            created_at_unix_seconds: 1,
        },
    )
    .unwrap();
    let Cli {
        command: Commands::Node {
            command: NodeCommands::Attach(args),
        },
    } = parse(&[
        "clusterflux",
        "node",
        "attach",
        "--tenant",
        "tenant-wrong",
        "--node",
        "node-wrong-tenant",
    ])
    else {
        panic!("wrong command");
    };

    let error = execute_node_attach(args, temp.path()).unwrap_err();

    assert!(error
        .to_string()
        .contains("conflicts with the authenticated tenant `tenant-authenticated`"));
    assert!(!node::local_node_credential_file(temp.path(), "node-wrong-tenant").exists());
}

#[test]
fn node_attach_without_coordinator_enrolls_and_persists_authenticated_scope() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let coordinator = listener.local_addr().unwrap().to_string();
    write_cli_session(
        temp.path(),
        &StoredCliSession {
            kind: "human".to_owned(),
            coordinator: coordinator.clone(),
            tenant: "tenant-authenticated".to_owned(),
            project: "project-authenticated".to_owned(),
            user: "user-authenticated".to_owned(),
            cli_session_credential_kind: "CliDeviceSession".to_owned(),
            session_secret: Some("session-secret".to_owned()),
            token_expiry_posture: "unknown_coordinator_session".to_owned(),
            expires_at: None,
            provider_tokens_exposed_to_cli: false,
            provider_tokens_sent_to_nodes: false,
            created_at_unix_seconds: 1,
        },
    )
    .unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        for response in [
            clusterflux_protocol::CoordinatorResponse::NodeEnrollmentExchanged {
                node: clusterflux_core::NodeId::from("node-attached"),
                tenant: clusterflux_core::TenantId::from("tenant-authenticated"),
                project: clusterflux_core::ProjectId::from("project-authenticated"),
                credential: clusterflux_core::NodeCredential {
                    node: clusterflux_core::NodeId::from("node-attached"),
                    tenant: clusterflux_core::TenantId::from("tenant-authenticated"),
                    project: clusterflux_core::ProjectId::from("project-authenticated"),
                    public_key_fingerprint: clusterflux_core::Digest::sha256("node-key"),
                    scope: "node:attach".to_owned(),
                    capability_policy_digest: clusterflux_core::Digest::sha256("policy"),
                    credential_kind: clusterflux_core::CredentialKind::NodeCredential,
                },
            },
            clusterflux_protocol::CoordinatorResponse::NodeHeartbeat {
                node: clusterflux_core::NodeId::from("node-attached"),
                epoch: 1,
            },
            clusterflux_protocol::CoordinatorResponse::NodeCapabilitiesRecorded {
                node: clusterflux_core::NodeId::from("node-attached"),
                node_descriptors: 1,
            },
        ] {
            let mut request = String::new();
            reader.read_line(&mut request).unwrap();
            let request: serde_json::Value = serde_json::from_str(&request).unwrap();
            assert_eq!(
                request
                    .pointer("/payload/tenant")
                    .or_else(|| request.pointer("/payload/request/tenant"))
                    .and_then(|value| value.as_str()),
                Some("tenant-authenticated")
            );
            assert_eq!(
                request
                    .pointer("/payload/project")
                    .or_else(|| request.pointer("/payload/request/project"))
                    .and_then(|value| value.as_str()),
                Some("project-authenticated")
            );
            serde_json::to_writer(&mut writer, &response).unwrap();
            writer.write_all(b"\n").unwrap();
        }
    });
    let Cli {
        command: Commands::Node {
            command: NodeCommands::Attach(args),
        },
    } = parse(&[
        "clusterflux",
        "node",
        "attach",
        "--node",
        "node-attached",
        "--enrollment-grant",
        "enrollment-grant",
    ])
    else {
        panic!("wrong command");
    };

    let report = execute_node_attach(args, temp.path()).unwrap();
    server.join().unwrap();

    assert_eq!(report.coordinator, coordinator);
    assert_eq!(
        report.plan.coordinator.as_deref(),
        Some(coordinator.as_str())
    );
    assert_eq!(report.tenant, "tenant-authenticated");
    assert_eq!(report.project, "project-authenticated");
    assert!(report.boundary.used_enrollment_exchange);
    let rendered = human_report(&serde_json::to_value(&report).unwrap());
    assert!(rendered.contains(&format!("coordinator: {coordinator}")));
    assert!(rendered.contains("tenant: tenant-authenticated"));
    assert!(rendered.contains("project: project-authenticated"));
    let credential_file = node::local_node_credential_file(temp.path(), "node-attached");
    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(credential_file).unwrap()).unwrap();
    assert_eq!(stored["coordinator"], coordinator);
    assert_eq!(stored["tenant"], "tenant-authenticated");
    assert_eq!(stored["project"], "project-authenticated");
}

#[cfg(unix)]
#[test]
fn node_attach_refuses_a_symlink_credential_target() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let node = "node/symlink";
    let file = node::local_node_credential_file(temp.path(), node);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    let target = temp.path().join("attacker-controlled.json");
    fs::write(&target, b"{}").unwrap();
    symlink(&target, &file).unwrap();

    let error = node::load_or_create_local_node_credential(temp.path(), node).unwrap_err();
    assert!(error.to_string().contains("symbolic link"));
}
