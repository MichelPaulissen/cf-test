use super::*;
use crate::NodeScopeKey;

#[test]
fn endpoint_advertisement_allows_only_the_bounded_node_clock_skew() {
    let mut service = CoordinatorService::new(90);
    service.set_server_time(100);
    let tenant = TenantId::from("tenant");
    let project = ProjectId::from("project");
    let node = NodeId::from("clock-skew-node");
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: tenant.to_string(),
            project: project.to_string(),
            node: node.to_string(),
            public_key: test_node_public_key(node.as_str()),
        })
        .unwrap();

    let advertisement = |expires_at| IrohEndpointAdvertisement {
        tenant: tenant.clone(),
        project: project.clone(),
        node: node.clone(),
        endpoint_id: format!("clock-skew-endpoint-{expires_at}"),
        generation: 1,
        relay_configuration_generation: 1,
        direct_addresses: vec!["127.0.0.1:41000".parse().unwrap()],
        relay_urls: Vec::new(),
        expires_at,
    };

    service
        .handle_report_iroh_endpoint_advertisement(
            tenant.to_string(),
            project.to_string(),
            node.to_string(),
            advertisement(165),
        )
        .unwrap();
    let error = service
        .handle_report_iroh_endpoint_advertisement(
            tenant.to_string(),
            project.to_string(),
            node.to_string(),
            advertisement(166),
        )
        .unwrap_err();
    assert!(error.to_string().contains("outside the coordinator policy"));
}

#[test]
fn iroh_interchange_exchanges_authorized_peers_and_publishes_after_verification() {
    let mut service = CoordinatorService::new(91);
    service.set_server_time(100);
    let tenant = TenantId::from("tenant");
    let project = ProjectId::from("project");
    let process = ProcessId::from("process");
    let source = NodeId::from("source-node");
    let destination = NodeId::from("destination-node");

    for node in [&source, &destination] {
        service
            .handle_request(CoordinatorRequest::AttachNode {
                tenant: tenant.to_string(),
                project: project.to_string(),
                node: node.to_string(),
                public_key: test_node_public_key(node.as_str()),
            })
            .unwrap();
        service
            .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
                tenant: tenant.to_string(),
                project: project.to_string(),
                node: node.to_string(),
                capabilities: linux_capabilities(),
                cached_environment_digests: Vec::new(),
                dependency_cache_digests: Vec::new(),
                source_snapshots: Vec::new(),
                artifact_locations: Vec::new(),
                online: true,
            })
            .unwrap();
    }

    for (node, endpoint_id, port) in [
        (&source, "source-iroh-endpoint", 41_001),
        (&destination, "destination-iroh-endpoint", 41_002),
    ] {
        service
            .handle_report_iroh_endpoint_advertisement(
                tenant.to_string(),
                project.to_string(),
                node.to_string(),
                IrohEndpointAdvertisement {
                    tenant: tenant.clone(),
                    project: project.clone(),
                    node: node.clone(),
                    endpoint_id: endpoint_id.to_owned(),
                    generation: 1,
                    relay_configuration_generation: 1,
                    direct_addresses: vec![format!("127.0.0.1:{port}").parse().unwrap()],
                    relay_urls: Vec::new(),
                    expires_at: 150,
                },
            )
            .unwrap();
    }

    let artifact = ArtifactId::from("verified-artifact");
    let digest = Digest::sha256("artifact bytes");
    let size = 14;
    service.artifact_registry.flush_metadata(ArtifactFlush {
        id: artifact.clone(),
        tenant: tenant.clone(),
        project: project.clone(),
        process: process.clone(),
        producer_task: TaskInstanceId::from("producer"),
        retaining_node: source.clone(),
        digest: digest.clone(),
        size,
    });

    let CoordinatorResponse::ArtifactTransferAuthorization {
        authorization: Some(destination_authorization),
        transfer: Some(record),
    } = service
        .handle_request_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            process.to_string(),
            destination.to_string(),
            artifact.to_string(),
            0,
        )
        .unwrap()
    else {
        panic!("expected destination artifact authorization");
    };
    assert_eq!(record.source_node, source);
    assert_eq!(record.destination_node, destination);
    assert_eq!(
        destination_authorization.peer.endpoint_id,
        "source-iroh-endpoint"
    );

    let CoordinatorResponse::ArtifactProviderAssignment {
        authorization: Some(provider_authorization),
        ..
    } = service
        .handle_poll_artifact_provider_assignment(
            tenant.to_string(),
            project.to_string(),
            source.to_string(),
        )
        .unwrap()
    else {
        panic!("expected source provider authorization");
    };
    assert_eq!(
        provider_authorization.peer.endpoint_id,
        "destination-iroh-endpoint"
    );
    assert_eq!(
        provider_authorization.transfer_secret,
        destination_authorization.transfer_secret
    );

    let provider_ready = service
        .handle_report_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            source.to_string(),
            record.transfer_id.clone(),
            ArtifactTransferState::Connecting,
            0,
            ClusterfluxPathKind::Direct,
            None,
            None,
            None,
        )
        .unwrap();
    let CoordinatorResponse::ArtifactTransferProgressAccepted {
        authorization: Some(provider_authorization),
        ..
    } = provider_ready
    else {
        panic!("provider readiness must return its refreshed pin authorization");
    };
    assert_eq!(
        provider_authorization.lease.expires_at,
        record.stream_ticket_expires_at
    );
    assert_eq!(
        provider_authorization.lease.active_lease_expires_at,
        record.expires_at
    );
    for state in [
        ArtifactTransferState::Transferring,
        ArtifactTransferState::Verifying,
    ] {
        service
            .handle_report_artifact_interchange(
                tenant.to_string(),
                project.to_string(),
                destination.to_string(),
                record.transfer_id.clone(),
                state,
                size,
                ClusterfluxPathKind::Direct,
                None,
                None,
                None,
            )
            .unwrap();
    }
    assert!(service
        .handle_report_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            destination.to_string(),
            record.transfer_id.clone(),
            ArtifactTransferState::Completed,
            size,
            ClusterfluxPathKind::Direct,
            None,
            Some(Digest::sha256("wrong")),
            Some(size),
        )
        .is_err());
    service
        .handle_report_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            destination.to_string(),
            record.transfer_id,
            ArtifactTransferState::Completed,
            size,
            ClusterfluxPathKind::Direct,
            None,
            Some(digest),
            Some(size),
        )
        .unwrap();
    let metadata = service
        .artifact_registry
        .metadata(&tenant, &project, &artifact)
        .unwrap();
    assert!(metadata.retaining_nodes.contains(&source));
    assert!(metadata.retaining_nodes.contains(&destination));
    let metrics = service.operational_metrics();
    assert_eq!(metrics.artifact_direct_body_bytes, size);
    assert_eq!(metrics.artifact_relayed_body_bytes, 0);
    assert_eq!(metrics.artifact_unknown_path_body_bytes, 0);

    let CoordinatorResponse::ArtifactTransferAuthorization {
        authorization: None,
        transfer: Some(local),
    } = service
        .handle_request_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            process.to_string(),
            destination.to_string(),
            artifact.to_string(),
            0,
        )
        .unwrap()
    else {
        panic!("a verified same-node artifact must not create another transfer");
    };
    assert_eq!(local.path_kind, ClusterfluxPathKind::Local);
    assert_eq!(local.bytes_completed, size);
    assert_eq!(local.total_bytes, size);
}

#[test]
fn iroh_interchange_reschedules_after_source_loss_and_cancels_with_process() {
    let mut service = CoordinatorService::new(92);
    service.set_server_time(100);
    let tenant = TenantId::from("tenant");
    let project = ProjectId::from("project");
    let process = ProcessId::from("process");
    let source_a = NodeId::from("source-a");
    let source_b = NodeId::from("source-b");
    let destination = NodeId::from("destination");

    for node in [&source_a, &source_b, &destination] {
        service
            .handle_request(CoordinatorRequest::AttachNode {
                tenant: tenant.to_string(),
                project: project.to_string(),
                node: node.to_string(),
                public_key: test_node_public_key(node.as_str()),
            })
            .unwrap();
        service
            .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
                tenant: tenant.to_string(),
                project: project.to_string(),
                node: node.to_string(),
                capabilities: linux_capabilities(),
                cached_environment_digests: Vec::new(),
                dependency_cache_digests: Vec::new(),
                source_snapshots: Vec::new(),
                artifact_locations: Vec::new(),
                online: true,
            })
            .unwrap();
    }
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: tenant.to_string(),
            project: project.to_string(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: process.to_string(),
            restart: false,
        })
        .unwrap();

    for (node, endpoint_id, port) in [
        (&source_a, "source-a-endpoint", 42_001),
        (&source_b, "source-b-endpoint", 42_002),
        (&destination, "destination-endpoint", 42_003),
    ] {
        service
            .handle_report_iroh_endpoint_advertisement(
                tenant.to_string(),
                project.to_string(),
                node.to_string(),
                IrohEndpointAdvertisement {
                    tenant: tenant.clone(),
                    project: project.clone(),
                    node: node.clone(),
                    endpoint_id: endpoint_id.to_owned(),
                    generation: 1,
                    relay_configuration_generation: 1,
                    direct_addresses: vec![format!("127.0.0.1:{port}").parse().unwrap()],
                    relay_urls: Vec::new(),
                    expires_at: 150,
                },
            )
            .unwrap();
    }

    let artifact = ArtifactId::from("alternate-source-artifact");
    let digest = Digest::sha256("artifact bytes");
    let size = 14;
    service.artifact_registry.flush_metadata(ArtifactFlush {
        id: artifact.clone(),
        tenant: tenant.clone(),
        project: project.clone(),
        process: process.clone(),
        producer_task: TaskInstanceId::from("producer"),
        retaining_node: source_a.clone(),
        digest: digest.clone(),
        size,
    });
    service
        .artifact_registry
        .record_verified_retaining_location(&tenant, &project, &artifact, &source_b, &digest, size)
        .unwrap();

    let CoordinatorResponse::ArtifactTransferAuthorization {
        authorization: Some(first_authorization),
        transfer: Some(first),
    } = service
        .handle_request_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            process.to_string(),
            destination.to_string(),
            artifact.to_string(),
            0,
        )
        .unwrap()
    else {
        panic!("expected the first retaining source");
    };
    assert_eq!(first.source_node, source_a);
    assert_eq!(first.attempt_count, 1);
    assert_eq!(first_authorization.peer.node, source_a);

    service
        .handle_report_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            source_a.to_string(),
            first.transfer_id,
            ArtifactTransferState::Failed,
            0,
            ClusterfluxPathKind::Unknown,
            Some(clusterflux_core::ArtifactTransferErrorCode::ArtifactMissingAtSource),
            None,
            None,
        )
        .unwrap();
    let metadata = service
        .artifact_registry
        .metadata(&tenant, &project, &artifact)
        .unwrap();
    assert!(!metadata.retaining_nodes.contains(&source_a));
    assert!(metadata.retaining_nodes.contains(&source_b));

    let CoordinatorResponse::ArtifactTransferAuthorization {
        authorization: Some(second_authorization),
        transfer: Some(second),
    } = service
        .handle_request_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            process.to_string(),
            destination.to_string(),
            artifact.to_string(),
            0,
        )
        .unwrap()
    else {
        panic!("expected an alternate retaining source");
    };
    assert_eq!(second.source_node, source_b);
    assert_eq!(second.attempt_count, 2);
    assert_eq!(second_authorization.peer.node, source_b);

    service
        .handle_request(CoordinatorRequest::CancelProcess {
            tenant: tenant.to_string(),
            project: project.to_string(),
            actor_user: "user".to_owned(),
            process: process.to_string(),
        })
        .unwrap();
    let cancelled = &service
        .interchange_registry
        .transfer(&second.transfer_id)
        .unwrap()
        .record;
    assert_eq!(cancelled.state, ArtifactTransferState::Cancelled);
    assert_eq!(
        cancelled.failure_code,
        Some(clusterflux_core::ArtifactTransferErrorCode::TransferCancelled)
    );
    let late_report = service
        .handle_report_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            destination.to_string(),
            second.transfer_id.clone(),
            ArtifactTransferState::Transferring,
            1,
            ClusterfluxPathKind::Direct,
            None,
            None,
            None,
        )
        .unwrap_err()
        .to_string();
    assert!(late_report.contains("transfer_cancelled"));
    let late_request = service
        .handle_request_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            process.to_string(),
            destination.to_string(),
            artifact.to_string(),
            0,
        )
        .unwrap_err()
        .to_string();
    assert!(late_request.contains("transfer_cancelled"));
    let CoordinatorResponse::ArtifactProviderAssignment {
        authorization,
        retired_transfer_ids,
    } = service
        .handle_poll_artifact_provider_assignment(
            tenant.to_string(),
            project.to_string(),
            source_b.to_string(),
        )
        .unwrap()
    else {
        panic!("expected provider assignment response");
    };
    assert!(authorization.is_none());
    assert!(retired_transfer_ids.contains(&second.transfer_id));
}

#[test]
fn ephemeral_drain_moves_sole_copy_then_releases_without_data_loss() {
    let mut service = CoordinatorService::new(93);
    service.set_server_time(100);
    let tenant = TenantId::from("tenant");
    let project = ProjectId::from("project");
    let process = ProcessId::from("drain-process");
    let source = NodeId::from("ephemeral-source");
    let destination = NodeId::from("persistent-destination");

    for node in [&source, &destination] {
        service
            .handle_request(CoordinatorRequest::AttachNode {
                tenant: tenant.to_string(),
                project: project.to_string(),
                node: node.to_string(),
                public_key: test_node_public_key(node.as_str()),
            })
            .unwrap();
        service
            .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
                tenant: tenant.to_string(),
                project: project.to_string(),
                node: node.to_string(),
                capabilities: linux_capabilities(),
                cached_environment_digests: Vec::new(),
                dependency_cache_digests: Vec::new(),
                source_snapshots: Vec::new(),
                artifact_locations: Vec::new(),
                online: true,
            })
            .unwrap();
    }
    for (node, endpoint_id, port) in [
        (&source, "ephemeral-endpoint", 43_001),
        (&destination, "persistent-endpoint", 43_002),
    ] {
        service
            .handle_report_iroh_endpoint_advertisement(
                tenant.to_string(),
                project.to_string(),
                node.to_string(),
                IrohEndpointAdvertisement {
                    tenant: tenant.clone(),
                    project: project.clone(),
                    node: node.clone(),
                    endpoint_id: endpoint_id.to_owned(),
                    generation: 1,
                    relay_configuration_generation: 1,
                    direct_addresses: vec![format!("127.0.0.1:{port}").parse().unwrap()],
                    relay_urls: Vec::new(),
                    expires_at: 150,
                },
            )
            .unwrap();
    }
    let artifact = ArtifactId::from("drain-artifact");
    let digest = Digest::sha256("required drain bytes");
    let size = 20;
    service.artifact_registry.flush_metadata(ArtifactFlush {
        id: artifact.clone(),
        tenant: tenant.clone(),
        project: project.clone(),
        process: process.clone(),
        producer_task: TaskInstanceId::from("producer"),
        retaining_node: source.clone(),
        digest: digest.clone(),
        size,
    });

    let CoordinatorResponse::NodeDrainStatus { status } = service
        .handle_begin_node_drain(
            tenant.to_string(),
            project.to_string(),
            source.to_string(),
            true,
            Some(90),
            None,
            None,
        )
        .unwrap()
    else {
        panic!("expected node drain status");
    };
    assert_eq!(status.state, clusterflux_core::NodeLifecycleState::Draining);
    assert!(status.provider_deadline_reached);
    assert_eq!(status.active_transfer_count, 1);
    assert!(!service.node_accepts_new_work(&NodeScopeKey::from_refs(&tenant, &project, &source)));
    assert!(status.blockers.iter().any(|blocker| {
        blocker.summary.contains("Moving artifact")
            && blocker.summary.contains(destination.as_str())
    }));

    let record = service
        .interchange_registry
        .transfers()
        .find(|transfer| transfer.record.artifact == artifact)
        .expect("drain must create a relocation transfer")
        .record
        .clone();
    assert_eq!(record.source_node, source);
    assert_eq!(record.destination_node, destination);
    service
        .handle_report_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            source.to_string(),
            record.transfer_id.clone(),
            ArtifactTransferState::Connecting,
            0,
            ClusterfluxPathKind::Direct,
            None,
            None,
            None,
        )
        .unwrap();
    for state in [
        ArtifactTransferState::Transferring,
        ArtifactTransferState::Verifying,
    ] {
        service
            .handle_report_artifact_interchange(
                tenant.to_string(),
                project.to_string(),
                destination.to_string(),
                record.transfer_id.clone(),
                state,
                size,
                ClusterfluxPathKind::Direct,
                None,
                None,
                None,
            )
            .unwrap();
    }
    service
        .handle_report_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            destination.to_string(),
            record.transfer_id,
            ArtifactTransferState::Completed,
            size,
            ClusterfluxPathKind::Direct,
            None,
            Some(digest),
            Some(size),
        )
        .unwrap();

    let CoordinatorResponse::NodeDrainStatus { status } = service
        .handle_begin_node_drain(
            tenant.to_string(),
            project.to_string(),
            source.to_string(),
            true,
            Some(90),
            None,
            None,
        )
        .unwrap()
    else {
        panic!("expected ready drain status");
    };
    assert_eq!(
        status.state,
        clusterflux_core::NodeLifecycleState::ReadyToRelease
    );
    let CoordinatorResponse::NodeDrainStatus { status } = service
        .handle_finalize_node_release(tenant.to_string(), project.to_string(), source.to_string())
        .unwrap()
    else {
        panic!("expected released drain status");
    };
    assert_eq!(status.state, clusterflux_core::NodeLifecycleState::Released);
    let metadata = service
        .artifact_registry
        .metadata(&tenant, &project, &artifact)
        .unwrap();
    assert_eq!(metadata.retaining_nodes, BTreeSet::from([destination]));
}

#[test]
fn explicit_release_is_idempotent_and_unblocks_a_sole_copy_drain() {
    let mut service = CoordinatorService::new(94);
    service.set_server_time(100);
    let tenant = TenantId::from("tenant");
    let project = ProjectId::from("project");
    let process = ProcessId::from("release-process");
    let node = NodeId::from("release-node");
    let task = TaskInstanceId::from("release-task");
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: tenant.to_string(),
            project: project.to_string(),
            node: node.to_string(),
            public_key: test_node_public_key(node.as_str()),
        })
        .unwrap();
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: tenant.to_string(),
            project: project.to_string(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: process.to_string(),
            restart: false,
        })
        .unwrap();
    service.task_registry.activate((
        tenant.clone(),
        project.clone(),
        process.clone(),
        node.clone(),
        task.clone(),
    ));
    let artifact = ArtifactId::from("released-artifact");
    let digest = Digest::sha256("release bytes");
    service.artifact_registry.flush_metadata(ArtifactFlush {
        id: artifact.clone(),
        tenant: tenant.clone(),
        project: project.clone(),
        process: process.clone(),
        producer_task: TaskInstanceId::from("producer"),
        retaining_node: node.clone(),
        digest: digest.clone(),
        size: 13,
    });
    let consumer_hold = clusterflux_core::ArtifactHoldReason::ConsumerTask {
        process: process.clone(),
        task: task.clone(),
    };
    service
        .artifact_registry
        .add_hold(&tenant, &project, &artifact, consumer_hold.clone(), 100)
        .unwrap();
    let first = service
        .handle_release_artifact(
            tenant.to_string(),
            project.to_string(),
            process.to_string(),
            node.to_string(),
            task.to_string(),
            artifact.to_string(),
            digest.clone(),
            13,
        )
        .unwrap();
    let second = service
        .handle_release_artifact(
            tenant.to_string(),
            project.to_string(),
            process.to_string(),
            node.to_string(),
            task.to_string(),
            artifact.to_string(),
            digest,
            13,
        )
        .unwrap();
    assert!(matches!(
        first,
        CoordinatorResponse::ArtifactReleased {
            hold_removed: true,
            ..
        }
    ));
    assert!(matches!(
        second,
        CoordinatorResponse::ArtifactReleased {
            hold_removed: false,
            ..
        }
    ));
    assert_eq!(
        service
            .artifact_registry
            .holds(&tenant, &project, &artifact),
        vec![clusterflux_core::ArtifactHold {
            reason: consumer_hold.clone(),
            created_at_epoch_seconds: 100,
        }],
        "Artifact::release removes only the owning process-retention hold"
    );
    service
        .artifact_registry
        .remove_hold(&tenant, &project, &artifact, &consumer_hold);
    service.task_registry.clear_active();
    let CoordinatorResponse::NodeDrainStatus { status } = service
        .handle_begin_node_drain(
            tenant.to_string(),
            project.to_string(),
            node.to_string(),
            true,
            None,
            None,
            None,
        )
        .unwrap()
    else {
        panic!("expected node drain status");
    };
    assert_eq!(
        status.state,
        clusterflux_core::NodeLifecycleState::ReadyToRelease
    );
}

#[test]
fn node_release_finalization_rechecks_blockers_and_hard_deadline_is_terminal() {
    let mut service = CoordinatorService::new(940);
    service.set_server_time(100);
    let tenant = TenantId::from("tenant");
    let project = ProjectId::from("project");
    let process = ProcessId::from("drain-fence-process");
    let node = NodeId::from("drain-fence-node");
    let task = TaskInstanceId::from("late-task");
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: tenant.to_string(),
            project: project.to_string(),
            node: node.to_string(),
            public_key: test_node_public_key(node.as_str()),
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: tenant.to_string(),
            project: project.to_string(),
            node: node.to_string(),
            capabilities: linux_capabilities(),
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap();
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: tenant.to_string(),
            project: project.to_string(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: process.to_string(),
            restart: false,
        })
        .unwrap();
    let CoordinatorResponse::NodeDrainStatus { status } = service
        .handle_begin_node_drain(
            tenant.to_string(),
            project.to_string(),
            node.to_string(),
            true,
            None,
            None,
            None,
        )
        .unwrap()
    else {
        panic!("expected node drain status");
    };
    assert_eq!(
        status.state,
        clusterflux_core::NodeLifecycleState::ReadyToRelease
    );

    // A blocker appearing after ReadyToRelease must fence release and preserve
    // the node's coordinator state.
    service.task_registry.activate((
        tenant.clone(),
        project.clone(),
        process.clone(),
        node.clone(),
        task.clone(),
    ));
    let CoordinatorResponse::NodeDrainStatus { status } = service
        .handle_finalize_node_release(tenant.to_string(), project.to_string(), node.to_string())
        .unwrap()
    else {
        panic!("expected fenced node release status");
    };
    assert_eq!(status.state, clusterflux_core::NodeLifecycleState::Draining);
    assert!(status
        .blockers
        .iter()
        .any(|blocker| blocker.kind == clusterflux_core::NodeDrainBlockerKind::RunningTask));
    assert!(service
        .node_registry
        .contains_node(&NodeScopeKey::from_refs(&tenant, &project, &node)));

    service
        .handle_begin_node_drain(
            tenant.to_string(),
            project.to_string(),
            node.to_string(),
            true,
            None,
            None,
            Some(100),
        )
        .unwrap();
    let CoordinatorResponse::NodeDrainStatus { status } = service
        .handle_finalize_node_release(tenant.to_string(), project.to_string(), node.to_string())
        .unwrap()
    else {
        panic!("expected hard-deadline release status");
    };
    assert_eq!(status.state, clusterflux_core::NodeLifecycleState::Released);
    assert!(status.hard_deadline_reached);
    assert!(status
        .release_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("hard drain deadline")));
    assert!(service
        .coordinator
        .active_process(&tenant, &project, &process)
        .is_none());
}

#[test]
fn artifact_assignment_offer_is_redelivered_until_idempotent_ack() {
    let mut service = CoordinatorService::new(95);
    service.set_server_time(100);
    let tenant = TenantId::from("tenant");
    let project = ProjectId::from("project");
    let process = ProcessId::from("ack-process");
    let source = NodeId::from("ack-source");
    let destination = NodeId::from("ack-destination");
    for node in [&source, &destination] {
        service
            .handle_request(CoordinatorRequest::AttachNode {
                tenant: tenant.to_string(),
                project: project.to_string(),
                node: node.to_string(),
                public_key: test_node_public_key(node.as_str()),
            })
            .unwrap();
        service
            .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
                tenant: tenant.to_string(),
                project: project.to_string(),
                node: node.to_string(),
                capabilities: linux_capabilities(),
                cached_environment_digests: Vec::new(),
                dependency_cache_digests: Vec::new(),
                source_snapshots: Vec::new(),
                artifact_locations: Vec::new(),
                online: true,
            })
            .unwrap();
    }
    for (node, endpoint_id, port) in [
        (&source, "ack-source-endpoint", 44_001),
        (&destination, "ack-destination-endpoint", 44_002),
    ] {
        service
            .handle_report_iroh_endpoint_advertisement(
                tenant.to_string(),
                project.to_string(),
                node.to_string(),
                IrohEndpointAdvertisement {
                    tenant: tenant.clone(),
                    project: project.clone(),
                    node: node.clone(),
                    endpoint_id: endpoint_id.to_owned(),
                    generation: 1,
                    relay_configuration_generation: 1,
                    direct_addresses: vec![format!("127.0.0.1:{port}").parse().unwrap()],
                    relay_urls: Vec::new(),
                    expires_at: 150,
                },
            )
            .unwrap();
    }
    let artifact = ArtifactId::from("ack-artifact");
    service.artifact_registry.flush_metadata(ArtifactFlush {
        id: artifact.clone(),
        tenant: tenant.clone(),
        project: project.clone(),
        process: process.clone(),
        producer_task: TaskInstanceId::from("producer"),
        retaining_node: source.clone(),
        digest: Digest::sha256("ack bytes"),
        size: 9,
    });
    let CoordinatorResponse::ArtifactTransferAuthorization {
        transfer: Some(record),
        ..
    } = service
        .handle_request_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            process.to_string(),
            destination.to_string(),
            artifact.to_string(),
            0,
        )
        .unwrap()
    else {
        panic!("expected transfer");
    };
    for _ in 0..2 {
        let CoordinatorResponse::ArtifactProviderAssignment {
            authorization: Some(authorization),
            ..
        } = service
            .handle_poll_artifact_provider_assignment(
                tenant.to_string(),
                project.to_string(),
                source.to_string(),
            )
            .unwrap()
        else {
            panic!("unacknowledged offer must be redelivered");
        };
        assert_eq!(authorization.lease.transfer_id, record.transfer_id);
    }
    for _ in 0..2 {
        let response = service
            .handle_acknowledge_artifact_assignment(
                tenant.to_string(),
                project.to_string(),
                source.to_string(),
                record.transfer_id.clone(),
                clusterflux_core::ArtifactAssignmentRole::Provider,
            )
            .unwrap();
        assert!(matches!(
            response,
            CoordinatorResponse::ArtifactAssignmentAcknowledged {
                state: clusterflux_core::ArtifactAssignmentState::Acknowledged,
                ..
            }
        ));
    }
    assert!(matches!(
        service
            .handle_poll_artifact_provider_assignment(
                tenant.to_string(),
                project.to_string(),
                source.to_string(),
            )
            .unwrap(),
        CoordinatorResponse::ArtifactProviderAssignment {
            authorization: None,
            ..
        }
    ));
    service.set_server_time(106);
    assert!(matches!(
        service
            .handle_poll_artifact_provider_assignment(
                tenant.to_string(),
                project.to_string(),
                source.to_string(),
            )
            .unwrap(),
        CoordinatorResponse::ArtifactProviderAssignment {
            authorization: Some(_),
            ..
        }
    ));
}

fn attach_live_interchange_test_node(
    service: &mut CoordinatorService,
    tenant: &TenantId,
    project: &ProjectId,
    node: &NodeId,
    endpoint_id: &str,
    port: u16,
) {
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: tenant.to_string(),
            project: project.to_string(),
            node: node.to_string(),
            public_key: test_node_public_key(node.as_str()),
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: tenant.to_string(),
            project: project.to_string(),
            node: node.to_string(),
            capabilities: linux_capabilities(),
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap();
    service
        .handle_report_iroh_endpoint_advertisement(
            tenant.to_string(),
            project.to_string(),
            node.to_string(),
            IrohEndpointAdvertisement {
                tenant: tenant.clone(),
                project: project.clone(),
                node: node.clone(),
                endpoint_id: endpoint_id.to_owned(),
                generation: 1,
                relay_configuration_generation: 1,
                direct_addresses: vec![format!("127.0.0.1:{port}").parse().unwrap()],
                relay_urls: Vec::new(),
                expires_at: 150,
            },
        )
        .unwrap();
}

#[test]
fn explicit_export_returns_before_bytes_and_uses_normal_background_assignments() {
    let mut service = CoordinatorService::new(951);
    service.set_server_time(100);
    let tenant = TenantId::from("export-tenant");
    let project = ProjectId::from("export-project");
    let process = ProcessId::from("export-process");
    let source = NodeId::from("export-source");
    let destination = NodeId::from("export-destination");
    attach_live_interchange_test_node(
        &mut service,
        &tenant,
        &project,
        &source,
        "export-source-endpoint",
        47_001,
    );
    attach_live_interchange_test_node(
        &mut service,
        &tenant,
        &project,
        &destination,
        "export-destination-endpoint",
        47_002,
    );
    let artifact = ArtifactId::from("explicit-export-artifact");
    let digest = Digest::sha256("explicit export bytes");
    service.artifact_registry.flush_metadata(ArtifactFlush {
        id: artifact.clone(),
        tenant: tenant.clone(),
        project: project.clone(),
        process: process.clone(),
        producer_task: TaskInstanceId::from("producer"),
        retaining_node: source.clone(),
        digest: digest.clone(),
        size: 21,
    });
    assert_eq!(
        service
            .artifact_registry
            .release_process_holds(&tenant, &project, &process),
        1,
        "normal process retirement should release the producer hold"
    );
    assert!(
        service
            .artifact_registry
            .holds(&tenant, &project, &artifact)
            .is_empty(),
        "the export itself must establish the new retention need"
    );

    let CoordinatorResponse::ArtifactExport {
        transfer: Some(transfer),
        already_present: false,
        receiver_node,
        artifact_size_bytes: 21,
    } = service
        .handle_export_artifact_to_node(
            tenant.to_string(),
            project.to_string(),
            "user".to_owned(),
            artifact.to_string(),
            destination.to_string(),
        )
        .unwrap()
    else {
        panic!("explicit export should return a submitted background transfer");
    };
    assert_eq!(receiver_node, destination);
    assert_eq!(transfer.state, ArtifactTransferState::SourceSelected);
    assert_eq!(transfer.bytes_completed, 0);

    let CoordinatorResponse::ArtifactProviderAssignment {
        authorization: Some(provider),
        ..
    } = service
        .handle_poll_artifact_provider_assignment(
            tenant.to_string(),
            project.to_string(),
            source.to_string(),
        )
        .unwrap()
    else {
        panic!("explicit export should use the normal provider assignment queue");
    };
    let CoordinatorResponse::ArtifactReceiverAssignment {
        authorization: Some(receiver),
    } = service
        .handle_poll_artifact_receiver_assignment(
            tenant.to_string(),
            project.to_string(),
            destination.to_string(),
        )
        .unwrap()
    else {
        panic!("explicit export should use the normal receiver assignment queue");
    };
    assert_eq!(provider.lease.transfer_id, transfer.transfer_id);
    assert_eq!(receiver.lease.transfer_id, transfer.transfer_id);
    assert_eq!(provider.transfer_secret, receiver.transfer_secret);

    service
        .artifact_registry
        .record_verified_retaining_location(
            &tenant,
            &project,
            &artifact,
            &destination,
            &digest,
            transfer.total_bytes,
        )
        .unwrap();
    let CoordinatorResponse::ArtifactExport {
        transfer: None,
        already_present: true,
        ..
    } = service
        .handle_export_artifact_to_node(
            tenant.to_string(),
            project.to_string(),
            "user".to_owned(),
            artifact.to_string(),
            destination.to_string(),
        )
        .unwrap()
    else {
        panic!("a repeated export should return immediately without a new transfer");
    };
}

#[test]
fn direct_required_transfer_accepts_verified_local_completion_without_network_metering() {
    let mut service = CoordinatorService::new(96);
    service.set_server_time(100);
    let tenant = TenantId::from("local-tenant");
    let project = ProjectId::from("local-project");
    let process = ProcessId::from("local-process");
    let source = NodeId::from("local-source");
    let destination = NodeId::from("local-destination");
    attach_live_interchange_test_node(
        &mut service,
        &tenant,
        &project,
        &source,
        "local-source-endpoint",
        45_001,
    );
    attach_live_interchange_test_node(
        &mut service,
        &tenant,
        &project,
        &destination,
        "local-destination-endpoint",
        45_002,
    );
    let artifact = ArtifactId::from("local-race-artifact");
    let digest = Digest::sha256("local race bytes");
    let size = 16;
    service.artifact_registry.flush_metadata(ArtifactFlush {
        id: artifact.clone(),
        tenant: tenant.clone(),
        project: project.clone(),
        process: process.clone(),
        producer_task: TaskInstanceId::from("producer"),
        retaining_node: source.clone(),
        digest: digest.clone(),
        size,
    });
    let CoordinatorResponse::ArtifactTransferAuthorization {
        transfer: Some(record),
        ..
    } = service
        .handle_request_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            process.to_string(),
            destination.to_string(),
            artifact.to_string(),
            0,
        )
        .unwrap()
    else {
        panic!("expected transfer authorization");
    };
    service
        .handle_report_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            source.to_string(),
            record.transfer_id.clone(),
            ArtifactTransferState::Connecting,
            0,
            ClusterfluxPathKind::Local,
            None,
            None,
            None,
        )
        .unwrap();
    for state in [
        ArtifactTransferState::Transferring,
        ArtifactTransferState::Verifying,
    ] {
        service
            .handle_report_artifact_interchange(
                tenant.to_string(),
                project.to_string(),
                destination.to_string(),
                record.transfer_id.clone(),
                state,
                size,
                ClusterfluxPathKind::Local,
                None,
                None,
                None,
            )
            .unwrap();
    }
    service
        .handle_report_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            destination.to_string(),
            record.transfer_id,
            ArtifactTransferState::Completed,
            size,
            ClusterfluxPathKind::Local,
            None,
            Some(digest),
            Some(size),
        )
        .unwrap();
    let metrics = service.operational_metrics();
    assert_eq!(metrics.artifact_direct_body_bytes, 0);
    assert_eq!(metrics.artifact_relayed_body_bytes, 0);
    assert_eq!(metrics.artifact_unknown_path_body_bytes, 0);
    assert!(service
        .artifact_registry
        .metadata(&tenant, &project, &artifact)
        .unwrap()
        .retaining_nodes
        .contains(&destination));
}

#[test]
fn relay_admission_exists_only_for_endpoint_scopes_with_an_active_transfer_need() {
    let mut service = CoordinatorService::new(99);
    service.set_server_time(100);
    service.artifact_interchange_configuration.relay =
        clusterflux_core::IrohRelayConfiguration::Custom(vec![
            clusterflux_core::ClusterfluxRelayConfig {
                url: "https://relay.clusterflux.example".to_owned(),
                access_token: None,
            },
        ]);
    let tenant = TenantId::from("relay-scope-tenant");
    let project = ProjectId::from("relay-scope-project");
    let process = ProcessId::from("relay-scope-process");
    let source = NodeId::from("relay-scope-source");
    let destination = NodeId::from("relay-scope-destination");
    attach_live_interchange_test_node(
        &mut service,
        &tenant,
        &project,
        &source,
        "relay-scope-source-endpoint",
        48_001,
    );
    attach_live_interchange_test_node(
        &mut service,
        &tenant,
        &project,
        &destination,
        "relay-scope-destination-endpoint",
        48_002,
    );
    assert!(service
        .authorized_relay_endpoint_scope("relay-scope-source-endpoint")
        .unwrap()
        .is_none());
    let artifact = ArtifactId::from("relay-scope-artifact");
    service.artifact_registry.flush_metadata(ArtifactFlush {
        id: artifact.clone(),
        tenant: tenant.clone(),
        project: project.clone(),
        process: process.clone(),
        producer_task: TaskInstanceId::from("producer"),
        retaining_node: source.clone(),
        digest: Digest::sha256("relay scoped bytes"),
        size: 18,
    });
    let CoordinatorResponse::ArtifactTransferAuthorization {
        transfer: Some(record),
        ..
    } = service
        .handle_request_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            process.to_string(),
            destination.to_string(),
            artifact.to_string(),
            0,
        )
        .unwrap()
    else {
        panic!("expected scoped transfer");
    };
    assert_eq!(
        service
            .authorized_relay_endpoint_scope("relay-scope-source-endpoint")
            .unwrap()
            .unwrap()
            .tenant,
        tenant
    );
    assert!(service
        .authorized_relay_endpoint_scope("relay-scope-destination-endpoint")
        .unwrap()
        .is_some());
    service
        .handle_report_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            source.to_string(),
            record.transfer_id,
            ArtifactTransferState::Failed,
            0,
            ClusterfluxPathKind::Unknown,
            Some(clusterflux_core::ArtifactTransferErrorCode::ConnectionFailed),
            None,
            None,
        )
        .unwrap();
    assert!(service
        .authorized_relay_endpoint_scope("relay-scope-source-endpoint")
        .unwrap()
        .is_none());
    assert!(service
        .authorized_relay_endpoint_scope("relay-scope-destination-endpoint")
        .unwrap()
        .is_none());
}

#[test]
fn active_transfer_lease_renews_beyond_ticket_for_hours_then_stalls_out() {
    let mut service = CoordinatorService::new(97);
    service.set_server_time(100);
    service
        .artifact_interchange_configuration
        .transfer_lease_ttl_seconds = 30;
    service
        .artifact_interchange_configuration
        .active_transfer_lease_ttl_seconds = 240;
    service
        .artifact_interchange_configuration
        .no_progress_timeout_seconds = 120;
    service
        .artifact_interchange_configuration
        .absolute_transfer_max_seconds = None;
    service
        .artifact_interchange_configuration
        .validate()
        .unwrap();
    let tenant = TenantId::from("lease-tenant");
    let project = ProjectId::from("lease-project");
    let process = ProcessId::from("lease-process");
    let source = NodeId::from("lease-source");
    let destination = NodeId::from("lease-destination");
    attach_live_interchange_test_node(
        &mut service,
        &tenant,
        &project,
        &source,
        "lease-source-endpoint",
        46_001,
    );
    attach_live_interchange_test_node(
        &mut service,
        &tenant,
        &project,
        &destination,
        "lease-destination-endpoint",
        46_002,
    );
    let artifact = ArtifactId::from("long-artifact");
    let digest = Digest::sha256("long bytes");
    service.artifact_registry.flush_metadata(ArtifactFlush {
        id: artifact.clone(),
        tenant: tenant.clone(),
        project: project.clone(),
        process: process.clone(),
        producer_task: TaskInstanceId::from("producer"),
        retaining_node: source.clone(),
        digest,
        size: 100,
    });
    let CoordinatorResponse::ArtifactTransferAuthorization {
        transfer: Some(record),
        ..
    } = service
        .handle_request_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            process.to_string(),
            destination.to_string(),
            artifact.to_string(),
            0,
        )
        .unwrap()
    else {
        panic!("expected long transfer authorization");
    };
    assert_eq!(record.stream_ticket_expires_at, 130);
    service
        .handle_report_artifact_interchange(
            tenant.to_string(),
            project.to_string(),
            source.to_string(),
            record.transfer_id.clone(),
            ArtifactTransferState::Connecting,
            0,
            ClusterfluxPathKind::Direct,
            None,
            None,
            None,
        )
        .unwrap();
    for minute in 1..=60_u64 {
        service.set_server_time(100 + minute * 60);
        service
            .handle_report_artifact_interchange(
                tenant.to_string(),
                project.to_string(),
                destination.to_string(),
                record.transfer_id.clone(),
                ArtifactTransferState::Transferring,
                minute,
                ClusterfluxPathKind::Direct,
                None,
                None,
                None,
            )
            .unwrap();
    }
    let renewed = &service
        .interchange_registry
        .transfer(&record.transfer_id)
        .unwrap()
        .record;
    assert_eq!(renewed.stream_ticket_expires_at, 130);
    assert_eq!(renewed.last_progress_at, 3_700);
    assert_eq!(renewed.expires_at, 3_940);
    let CoordinatorResponse::ArtifactProviderAssignment {
        authorization: Some(provider_authorization),
        ..
    } = service
        .handle_poll_artifact_provider_assignment(
            tenant.to_string(),
            project.to_string(),
            source.to_string(),
        )
        .unwrap()
    else {
        panic!("receiver lease renewal must redeliver the refreshed provider pin");
    };
    assert_eq!(provider_authorization.lease.active_lease_expires_at, 3_940);
    service.set_server_time(3_821);
    let _ = service
        .handle_poll_artifact_provider_assignment(
            tenant.to_string(),
            project.to_string(),
            source.to_string(),
        )
        .unwrap();
    let expired = &service
        .interchange_registry
        .transfer(&record.transfer_id)
        .unwrap()
        .record;
    assert_eq!(expired.state, ArtifactTransferState::Expired);
    assert_eq!(
        expired.failure_code,
        Some(clusterflux_core::ArtifactTransferErrorCode::TransferLeaseExpired)
    );
}

#[test]
fn tenant_transfer_capacity_rejects_a_storm_without_blocking_another_tenant() {
    let mut service = CoordinatorService::new(98);
    service.set_server_time(100);
    service
        .artifact_interchange_configuration
        .max_active_transfers_per_tenant = 1;
    let project = ProjectId::from("capacity-project");
    let tenant_a = TenantId::from("capacity-tenant-a");
    let tenant_b = TenantId::from("capacity-tenant-b");
    let process_a = ProcessId::from("capacity-process-a");
    let process_b = ProcessId::from("capacity-process-b");
    let source_a = NodeId::from("capacity-source-a");
    let destination_a = NodeId::from("capacity-destination-a");
    let source_b = NodeId::from("capacity-source-b");
    let destination_b = NodeId::from("capacity-destination-b");
    for (tenant, node, endpoint, port) in [
        (&tenant_a, &source_a, "capacity-source-a-endpoint", 47_001),
        (
            &tenant_a,
            &destination_a,
            "capacity-destination-a-endpoint",
            47_002,
        ),
        (&tenant_b, &source_b, "capacity-source-b-endpoint", 47_003),
        (
            &tenant_b,
            &destination_b,
            "capacity-destination-b-endpoint",
            47_004,
        ),
    ] {
        attach_live_interchange_test_node(&mut service, tenant, &project, node, endpoint, port);
    }
    for (tenant, process, source, artifact) in [
        (&tenant_a, &process_a, &source_a, "artifact-a-1"),
        (&tenant_a, &process_a, &source_a, "artifact-a-2"),
        (&tenant_b, &process_b, &source_b, "artifact-b-1"),
    ] {
        service.artifact_registry.flush_metadata(ArtifactFlush {
            id: ArtifactId::from(artifact),
            tenant: tenant.clone(),
            project: project.clone(),
            process: process.clone(),
            producer_task: TaskInstanceId::from("producer"),
            retaining_node: source.clone(),
            digest: Digest::sha256(artifact),
            size: 10,
        });
    }
    service
        .handle_request_artifact_interchange(
            tenant_a.to_string(),
            project.to_string(),
            process_a.to_string(),
            destination_a.to_string(),
            "artifact-a-1".to_owned(),
            0,
        )
        .unwrap();
    let tenant_a_overflow = service
        .handle_request_artifact_interchange(
            tenant_a.to_string(),
            project.to_string(),
            process_a.to_string(),
            destination_a.to_string(),
            "artifact-a-2".to_owned(),
            0,
        )
        .unwrap_err()
        .to_string();
    assert!(tenant_a_overflow.contains("capacity_unavailable"));
    let tenant_b_result = service
        .handle_request_artifact_interchange(
            tenant_b.to_string(),
            project.to_string(),
            process_b.to_string(),
            destination_b.to_string(),
            "artifact-b-1".to_owned(),
            0,
        )
        .unwrap();
    assert!(matches!(
        tenant_b_result,
        CoordinatorResponse::ArtifactTransferAuthorization {
            authorization: Some(_),
            transfer: Some(_),
        }
    ));
    assert_eq!(service.interchange_registry.len(), 2);
}
