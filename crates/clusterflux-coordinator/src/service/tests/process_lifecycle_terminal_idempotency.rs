use super::*;

fn terminal_completion_request(node: &str, stdout_tail: &str) -> CoordinatorRequest {
    CoordinatorRequest::TaskCompleted {
        tenant: "tenant".to_owned(),
        project: "project".to_owned(),
        process: "assignment-process".to_owned(),
        node: node.to_owned(),
        task: "assignment-task".to_owned(),
        terminal_state: Some(TaskTerminalState::Completed),
        status_code: Some(0),
        stdout_bytes: stdout_tail.len() as u64,
        stderr_bytes: 0,
        stdout_tail: stdout_tail.to_owned(),
        stderr_tail: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        artifact_path: None,
        artifact_digest: None,
        artifact_size_bytes: None,
        result: None,
    }
}

#[test]
fn committed_terminal_mutations_replay_after_response_loss_and_reject_conflicts() {
    let mut service = CoordinatorService::new(7);
    service.set_server_time(100);
    attach_live_process_worker(&mut service, "node-a");
    attach_live_process_worker(&mut service, "node-b");
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "other-tenant".to_owned(),
            project: "other-project".to_owned(),
            node: "node-a".to_owned(),
            public_key: test_node_public_key("node-a"),
        })
        .unwrap();
    start_assignment_lifecycle_process(&mut service);
    launch_assignment_lifecycle_task(&mut service);
    let assignment = poll_process_assignment(&mut service, "node-a");
    let authority = assignment_authority(&assignment);
    service
        .handle_request(signed_node_request_auto_with_private_key_and_authority(
            CoordinatorRequest::AcknowledgeNodeAssignment {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: "node-a".to_owned(),
                assignment_id: assignment.assignment_id,
                lease_epoch: assignment.offer_epoch,
            },
            &test_node_private_key("node-a"),
            Some(authority.clone()),
        ))
        .unwrap();

    let metadata = CoordinatorRequest::ReportVfsMetadata {
        tenant: "tenant".to_owned(),
        project: "project".to_owned(),
        process: "assignment-process".to_owned(),
        node: "node-a".to_owned(),
        task: "assignment-task".to_owned(),
        artifact_path: None,
        artifact_digest: None,
        artifact_size_bytes: None,
        large_bytes_uploaded: false,
    };
    let first_metadata = service
        .handle_request(signed_assignment_operation_for_test(
            metadata.clone(),
            "node-a",
            "report_vfs_metadata",
            authority.clone(),
            "metadata-operation",
        ))
        .unwrap();
    let replayed_metadata = service
        .handle_request(signed_assignment_operation_for_test(
            metadata.clone(),
            "node-a",
            "report_vfs_metadata",
            authority.clone(),
            "metadata-operation",
        ))
        .unwrap();
    assert_eq!(replayed_metadata, first_metadata);

    let completion = terminal_completion_request("node-a", "committed output");
    let committed_response = service
        .handle_request(signed_assignment_operation_for_test(
            completion.clone(),
            "node-a",
            "task_completed",
            authority.clone(),
            "completion-operation",
        ))
        .unwrap();
    let persisted_after_lost_response = service.coordinator.durable_state().clone();

    let mut restarted = CoordinatorService::new(8);
    *restarted.coordinator.durable_state_mut() = persisted_after_lost_response;
    let metadata_after_terminal = restarted
        .handle_request(signed_assignment_operation_for_test(
            metadata,
            "node-a",
            "report_vfs_metadata",
            authority.clone(),
            "metadata-operation",
        ))
        .unwrap();
    assert_eq!(metadata_after_terminal, first_metadata);
    let replayed_response = restarted
        .handle_request(signed_assignment_operation_for_test(
            completion,
            "node-a",
            "task_completed",
            authority.clone(),
            "completion-operation",
        ))
        .unwrap();
    assert_eq!(replayed_response, committed_response);

    let conflict = restarted
        .handle_request(signed_assignment_operation_for_test(
            terminal_completion_request("node-a", "changed output"),
            "node-a",
            "task_completed",
            authority.clone(),
            "completion-operation",
        ))
        .unwrap_err();
    assert!(matches!(
        conflict,
        CoordinatorServiceError::TerminalOperationConflict
    ));

    let mut stale_authority = authority.clone();
    stale_authority.offer_epoch = stale_authority.offer_epoch.saturating_add(1);
    assert!(restarted
        .handle_request(signed_assignment_operation_for_test(
            terminal_completion_request("node-a", "committed output"),
            "node-a",
            "task_completed",
            stale_authority,
            "completion-operation",
        ))
        .is_err());
    assert!(restarted
        .handle_request(signed_assignment_operation_for_test(
            terminal_completion_request("node-b", "committed output"),
            "node-b",
            "task_completed",
            authority.clone(),
            "completion-operation",
        ))
        .is_err());

    let mut cross_tenant = terminal_completion_request("node-a", "committed output");
    let CoordinatorRequest::TaskCompleted {
        tenant, project, ..
    } = &mut cross_tenant
    else {
        unreachable!()
    };
    *tenant = "other-tenant".to_owned();
    *project = "other-project".to_owned();
    assert!(restarted
        .handle_request(signed_assignment_operation_for_test(
            cross_tenant,
            "node-a",
            "task_completed",
            authority,
            "completion-operation",
        ))
        .is_err());
}
