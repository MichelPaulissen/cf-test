use super::*;

fn stored_session(project: &Path, coordinator: String) {
    write_cli_session(
        project,
        &StoredCliSession {
            kind: "human".to_owned(),
            coordinator,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            user: "user".to_owned(),
            cli_session_credential_kind: "CliDeviceSession".to_owned(),
            session_secret: Some("session-secret".to_owned()),
            token_expiry_posture: "expires_at".to_owned(),
            expires_at: Some("4102444800".to_owned()),
            provider_tokens_exposed_to_cli: false,
            provider_tokens_sent_to_nodes: false,
            created_at_unix_seconds: 1,
        },
    )
    .unwrap();
}

fn run_record(run: &str, state: &str, process: Option<&str>) -> Value {
    json!({
        "run_id": run,
        "primary_trigger_id": "trigger-1",
        "tenant": "tenant",
        "project": "project",
        "repository_id": "github:owner/repository",
        "commit_sha": "1111111111111111111111111111111111111111",
        "git_ref": "refs/heads/main",
        "trusted": true,
        "workflow_tree_digest": null,
        "bundle_digest": null,
        "state": state,
        "process_id": process,
        "created_at": 1,
        "started_at": if process.is_some() { Some(2) } else { None },
        "ended_at": if matches!(state, "completed" | "failed" | "cancelled") { Some(3) } else { None },
        "failure_code": if state == "failed" { Some("process_failed") } else { None },
        "failure_message": if state == "failed" { Some("task failed") } else { None },
        "publication_tag": null,
        "publication_url": null
    })
}

fn scope() -> CliScopeArgs {
    CliScopeArgs {
        coordinator: None,
        tenant: "tenant".to_owned(),
        project: "project".to_owned(),
        user: "user".to_owned(),
        json: true,
    }
}

#[test]
fn retry_and_trigger_reports_bind_the_returned_run_to_wait_guidance() {
    for trigger in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        stored_session(temp.path(), address.clone());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut request)
                .unwrap();
            let request: Value = serde_json::from_str(&request).unwrap();
            assert_eq!(
                request["payload"]["request"]["type"],
                if trigger {
                    "trigger_automated_run"
                } else {
                    "retry_automated_run"
                }
            );
            stream
                .write_all(
                    format!(
                        "{}\n",
                        json!({
                            "type": "automated_run",
                            "run": run_record("run-new", "accepted", None),
                            "actor": "user"
                        })
                    )
                    .as_bytes(),
                )
                .unwrap();
        });
        let report = if trigger {
            run_trigger_report(
                RunTriggerArgs {
                    repository: RepositoryId::from("github:owner/repository"),
                    git_ref: "refs/heads/main".to_owned(),
                    commit: None,
                    scope: scope(),
                },
                temp.path(),
            )
            .unwrap()
        } else {
            run_retry_report(
                RunRetryArgs {
                    run: RunId::from("run-old"),
                    scope: scope(),
                },
                temp.path(),
            )
            .unwrap()
        };
        server.join().unwrap();
        assert_eq!(report["run"]["run_id"], "run-new");
        assert_eq!(report["guidance"]["recommended"]["kind"], "wait");
        let argv = report["guidance"]["recommended"]["command"]
            .as_array()
            .unwrap();
        assert!(argv.iter().any(|argument| argument == "run-new"));
        assert!(argv.iter().any(|argument| argument == "30m"));
    }
}

#[test]
fn diagnose_returns_the_failed_attempt_and_its_bounded_tail() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    stored_session(temp.path(), address);
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        for response in [
            json!({"type":"automated_run","run":run_record("run-failed","failed",Some("vp")),"actor":"user"}),
            json!({"type":"task_snapshots","snapshots":[{
                "process":"vp","task":"task-1","attempt_id":"attempt-2","attempt_number":2,
                "task_definition":"definition-1","display_name":"build","state":"failed",
                "current":true,"node":"node-1","environment_id":null,"environment_digest":null,
                "argument_summary":[],"handle_summary":[],"command_state":"failed",
                "vfs_checkpoint":"none","probe_symbol":null,"source_path":null,"source_line":null,
                "restart_compatible":true,"failure_policy":"fail_fast","artifact_path":null,
                "artifact_digest":null,"artifact_size_bytes":null,"status_code":1,"error":"compile failed"
            }]}),
            json!({"type":"task_events","events":[{
                "tenant":"tenant","project":"project","process":"vp","node":"node-1",
                "executor":"node","task_definition":"definition-1","task":"task-1",
                "attempt_id":"attempt-2","terminal_state":"failed","status_code":1,
                "stdout_bytes":3,"stderr_bytes":7,"stdout_tail":"out","stderr_tail":"failure",
                "stdout_truncated":false,"stderr_truncated":true,"artifact_path":null,
                "artifact_digest":null,"artifact_size_bytes":null,"result":null
            }]}),
        ] {
            let mut request = String::new();
            reader.read_line(&mut request).unwrap();
            stream
                .write_all(format!("{response}\n").as_bytes())
                .unwrap();
        }
    });
    let report = run_diagnose_report(
        RunDiagnoseArgs {
            run: RunId::from("run-failed"),
            scope: scope(),
        },
        temp.path(),
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(report["run_failure"]["code"], "process_failed");
    assert_eq!(report["failed_task"]["task"], "task-1");
    assert_eq!(report["failed_task"]["attempt_id"], "attempt-2");
    assert_eq!(report["log_tail"]["stderr"], "failure");
    assert_eq!(report["log_tail"]["stderr_truncated"], true);
    assert_eq!(report["diagnostic_output_bounded"], true);
    assert_eq!(report["guidance"]["alternatives"][0]["kind"], "retry");
}

#[test]
fn webhook_deliveries_is_bounded_and_redacted() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    stored_session(temp.path(), address);
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut request)
            .unwrap();
        assert!(request.contains("list_webhook_deliveries"));
        stream.write_all(format!("{}\n", json!({
            "type":"webhook_deliveries",
            "deliveries":[{
                "sequence":1,"binding_id":"binding-1","tenant":"tenant","project":"project",
                "repository_id":"github:owner/repository","delivery_id":"delivery-1",
                "commit_sha":"1111111111111111111111111111111111111111","git_ref":"refs/heads/main",
                "outcome":"accepted","run_id":"run-1","reason_code":null,"received_at":1
            }],
            "actor":"user"
        })).as_bytes()).unwrap();
    });
    let report =
        webhook_deliveries_report(WebhookDeliveriesArgs { scope: scope() }, temp.path()).unwrap();
    server.join().unwrap();
    assert_eq!(report["bounded"], true);
    assert_eq!(report["deliveries"][0]["run_id"], "run-1");
    let encoded = serde_json::to_string(&report).unwrap();
    assert!(!encoded.contains("signature"));
    assert!(!encoded.contains("session-secret"));
}

#[test]
fn node_doctor_is_read_only_and_reports_remote_runtime_facts() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    stored_session(temp.path(), address);
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut request)
            .unwrap();
        assert!(request.contains("list_node_summaries"));
        stream
            .write_all(
                format!(
                    "{}\n",
                    json!({
                        "type":"node_summaries",
                        "nodes":[{
                            "id":"node-1","display_name":"node-1","credential_state":"enrolled",
                            "runtime_state":"ready","online":true,"stale":false,
                            "last_seen_epoch_seconds":1,"capabilities_known":true,
                            "automatic_workflow_compilation":"ready",
                            "capabilities":{
                                "os":"Linux","arch":"x86_64","capabilities":[],
                                "environment_backends":["Container"],"source_providers":[]
                            },
                            "artifact_connectivity":{
                                "endpoint_advertised":false,"recent_path":"unknown",
                                "recent_direct_failure":false,"relay_policy":"direct_required"
                            }
                        }],
                        "actor":"user"
                    })
                )
                .as_bytes(),
            )
            .unwrap();
    });
    let credential = crate::node::local_node_credential_file(temp.path(), "node-1");
    assert!(!credential.exists());
    let report = node_doctor_report(
        NodeDoctorArgs {
            scope: scope(),
            node: Some("node-1".to_owned()),
            full: false,
            environment: None,
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    server.join().unwrap();
    assert!(
        !credential.exists(),
        "node doctor must not create an identity"
    );
    assert_eq!(report["read_only"], true);
    assert_eq!(report["coordinator_identity_enrolled"], true);
    assert_eq!(report["node_online"], true);
    assert_eq!(report["container_backend_reported"], true);
    assert_eq!(report["automatic_workflow_compilation"], "ready");
    assert_eq!(report["local_identity"]["present"], false);
}
