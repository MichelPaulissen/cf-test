#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::net::TcpListener;
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use clusterflux_source::snapshot_project;

use super::*;

#[cfg(unix)]
fn start_running_control_server() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let coordinator = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        loop {
            let mut request = String::new();
            match reader.read_line(&mut request) {
                Ok(0) | Err(_) => break,
                Ok(_) => stream
                    .write_all(b"{\"type\":\"task_control\",\"process\":\"vp\",\"task\":\"task\",\"cancel_requested\":false,\"abort_requested\":false}\n")
                    .unwrap(),
            }
        }
    });
    (coordinator, server)
}

#[cfg(unix)]
fn start_reconnecting_control_server() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let coordinator = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let (interrupted, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(interrupted.try_clone().unwrap())
            .read_line(&mut request)
            .unwrap();
        assert!(!request.trim().is_empty());
        drop(interrupted);

        let (mut recovered, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(recovered.try_clone().unwrap());
        loop {
            let mut request = String::new();
            match reader.read_line(&mut request) {
                Ok(0) | Err(_) => break,
                Ok(_) => recovered
                    .write_all(b"{\"type\":\"task_control\",\"process\":\"vp\",\"task\":\"task\",\"cancel_requested\":false,\"abort_requested\":false}\n")
                    .unwrap(),
            }
        }
    });
    (coordinator, server)
}

#[cfg(unix)]
fn test_controlled_runner(
    coordinator: String,
    timeout: Duration,
) -> CoordinatorControlledProcessRunner {
    CoordinatorControlledProcessRunner {
        args: Args {
            coordinator,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            project_root: None,
            node: "node".to_owned(),
            enrollment_grant: None,
            public_key: None,
            control_poll_ms: 0,
            assignment_poll_ms: 1,
            coordinator_reconnect_max_seconds: 0,
            task_cpus: 2,
            task_memory_gib: 2,
            task_pids_limit: 256,
            emit_ready: false,
            worker: true,
            capabilities: Vec::new(),
            dangerous_allow_native_commands: false,
            no_workflow_compilation: true,
            system_tasks_only: false,
            system_compiler_image: None,
            system_compiler_runsc_version: None,
            system_compiler_sandbox: "podman".to_owned(),
            system_compiler_podman: "podman".to_owned(),
            system_compiler_runsc: "runsc".to_owned(),
            system_compiler_package_verified: false,
            system_compiler_package_dir: None,
            ephemeral: false,
            provider_deadline_epoch_seconds: None,
            soft_drain_deadline_epoch_seconds: None,
            hard_drain_deadline_epoch_seconds: None,
            ephemeral_startup_deadline_seconds: 60,
            ephemeral_idle_after_work_seconds: 30,
            debug_freeze_timeout_ms: 5_000,
            artifact_retention: crate::task_artifacts::NodeArtifactRetentionLimits::default(),
        },
        process: "vp".to_owned(),
        task: "task".to_owned(),
        node_private_key: clusterflux_core::derive_ed25519_private_key_from_seed(
            "controlled-runner-test",
        ),
        assignment_authority: clusterflux_core::AssignmentAuthority {
            assignment_id: "controlled-runner-assignment".to_owned(),
            attempt_id: "controlled-runner-attempt".to_owned(),
            offer_epoch: 1,
        },
        debug_control: Arc::new(WasmDebugControl::default()),
        command_status: Arc::new(Mutex::new(None)),
        stdout_source_bytes: Arc::new(AtomicU64::new(0)),
        stderr_source_bytes: Arc::new(AtomicU64::new(0)),
        timeout,
        configured_secrets: Vec::new(),
        local_abort_requested: Arc::new(AtomicBool::new(false)),
    }
}

#[cfg(unix)]
#[test]
fn controlled_process_runner_kills_running_group_when_abort_is_polled() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let coordinator = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut request)
            .unwrap();
        assert!(!request.trim().is_empty());
        stream
                .write_all(b"{\"type\":\"task_control\",\"process\":\"vp\",\"task\":\"task\",\"cancel_requested\":false,\"abort_requested\":true}\n")
                .unwrap();
    });
    let mut runner = CoordinatorControlledProcessRunner {
        args: Args {
            coordinator,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            project_root: None,
            node: "node".to_owned(),
            enrollment_grant: None,
            public_key: None,
            control_poll_ms: 0,
            assignment_poll_ms: 1,
            coordinator_reconnect_max_seconds: 0,
            task_cpus: 2,
            task_memory_gib: 2,
            task_pids_limit: 256,
            emit_ready: false,
            worker: true,
            capabilities: Vec::new(),
            dangerous_allow_native_commands: false,
            no_workflow_compilation: true,
            system_tasks_only: false,
            system_compiler_image: None,
            system_compiler_runsc_version: None,
            system_compiler_sandbox: "podman".to_owned(),
            system_compiler_podman: "podman".to_owned(),
            system_compiler_runsc: "runsc".to_owned(),
            system_compiler_package_verified: false,
            system_compiler_package_dir: None,
            ephemeral: false,
            provider_deadline_epoch_seconds: None,
            soft_drain_deadline_epoch_seconds: None,
            hard_drain_deadline_epoch_seconds: None,
            ephemeral_startup_deadline_seconds: 60,
            ephemeral_idle_after_work_seconds: 30,
            debug_freeze_timeout_ms: 5_000,
            artifact_retention: crate::task_artifacts::NodeArtifactRetentionLimits::default(),
        },
        process: "vp".to_owned(),
        task: "task".to_owned(),
        node_private_key: clusterflux_core::derive_ed25519_private_key_from_seed(
            "controlled-runner-test",
        ),
        assignment_authority: clusterflux_core::AssignmentAuthority {
            assignment_id: "controlled-runner-assignment".to_owned(),
            attempt_id: "controlled-runner-attempt".to_owned(),
            offer_epoch: 1,
        },
        debug_control: Arc::new(WasmDebugControl::default()),
        command_status: Arc::new(Mutex::new(None)),
        stdout_source_bytes: Arc::new(AtomicU64::new(0)),
        stderr_source_bytes: Arc::new(AtomicU64::new(0)),
        timeout: Duration::from_secs(30),
        configured_secrets: Vec::new(),
        local_abort_requested: Arc::new(AtomicBool::new(false)),
    };
    let started = Instant::now();
    let error = runner
        .run(&PodmanCommand {
            program: "sh".to_owned(),
            args: vec!["-c".to_owned(), "sleep 30 & wait".to_owned()],
            working_directory: None,
            environment: BTreeMap::new(),
        })
        .unwrap_err();
    server.join().unwrap();

    assert!(matches!(error, BackendError::Cancelled(_)));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[cfg(unix)]
#[test]
fn controlled_process_runner_survives_a_transient_control_disconnect() {
    let (coordinator, server) = start_reconnecting_control_server();
    let mut runner = test_controlled_runner(coordinator, Duration::from_secs(5));

    let output = runner
        .run(&PodmanCommand {
            program: "sh".to_owned(),
            args: vec!["-c".to_owned(), "sleep 1".to_owned()],
            working_directory: None,
            environment: BTreeMap::new(),
        })
        .unwrap();
    server.join().unwrap();

    assert_eq!(output.status_code, Some(0));
    assert!(runner
        .command_status
        .lock()
        .unwrap()
        .as_deref()
        .is_some_and(|status| status.contains("exited with status")));
}

#[cfg(unix)]
#[test]
fn command_timeout_is_bounded_and_a_later_command_still_runs() {
    let (coordinator, server) = start_running_control_server();
    let mut runner = test_controlled_runner(coordinator, Duration::from_millis(120));
    let started = Instant::now();
    let error = runner
        .run(&PodmanCommand {
            program: "sh".to_owned(),
            args: vec!["-c".to_owned(), "sleep 30 & wait".to_owned()],
            working_directory: None,
            environment: BTreeMap::new(),
        })
        .unwrap_err();
    assert!(error.to_string().contains("timeout"));
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(runner);
    server.join().unwrap();

    let (coordinator, server) = start_running_control_server();
    let mut runner = test_controlled_runner(coordinator, Duration::from_secs(5));
    let output = runner
        .run(&PodmanCommand {
            program: "sh".to_owned(),
            args: vec!["-c".to_owned(), "printf healthy".to_owned()],
            working_directory: None,
            environment: BTreeMap::new(),
        })
        .unwrap();
    assert_eq!(output.status_code, Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "healthy");
    drop(runner);
    server.join().unwrap();
}

#[test]
fn command_source_verification_rejects_a_changed_checkout() {
    let checkout = tempfile::tempdir().unwrap();
    std::fs::write(checkout.path().join("source.c"), "int value = 1;\n").unwrap();
    let expected = snapshot_project(checkout.path()).unwrap().digest;
    verify_source_snapshot(checkout.path(), &expected).unwrap();

    std::fs::write(checkout.path().join("source.c"), "int value = 2;\n").unwrap();
    let error = verify_source_snapshot(checkout.path(), &expected).unwrap_err();

    assert!(error.contains("source snapshot mismatch"));
    assert!(error.contains(expected.as_str()));
}

#[test]
fn exact_revision_snapshot_returns_its_authoritative_handle() {
    let checkout = tempfile::tempdir().unwrap();
    std::fs::write(checkout.path().join("source.c"), "int value = 1;\n").unwrap();
    let checkout_digest = snapshot_project(checkout.path()).unwrap().digest;
    let revision_handle = Digest::from_parts([
        b"clusterflux-git-revision:v1".as_slice(),
        b"github:example/project".as_slice(),
        b"https://github.com/example/project.git".as_slice(),
        b"0123456789abcdef0123456789abcdef01234567".as_slice(),
    ]);
    assert_ne!(checkout_digest, revision_handle);
    let revision = clusterflux_core::RepositoryRevision {
        repository_id: clusterflux_core::RepositoryId::from("github:example/project"),
        clone_url: "https://github.com/example/project.git".to_owned(),
        commit_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        source_snapshot: revision_handle.clone(),
    };

    assert_eq!(
        authoritative_source_snapshot(
            checkout.path(),
            Some(&revision_handle),
            Some(&revision),
            || false,
        )
        .unwrap(),
        revision_handle
    );
}

#[test]
fn exact_revision_snapshot_rejects_a_different_task_handle() {
    let checkout = tempfile::tempdir().unwrap();
    let revision = clusterflux_core::RepositoryRevision {
        repository_id: clusterflux_core::RepositoryId::from("github:example/project"),
        clone_url: "https://github.com/example/project.git".to_owned(),
        commit_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        source_snapshot: Digest::from_parts([b"revision".as_slice()]),
    };
    let different_handle = Digest::from_parts([b"different".as_slice()]);

    let error = authoritative_source_snapshot(
        checkout.path(),
        Some(&different_handle),
        Some(&revision),
        || false,
    )
    .unwrap_err();

    assert!(error.contains("does not match task source handle"));
}

#[test]
fn command_environment_verification_rejects_a_changed_recipe() {
    let checkout = tempfile::tempdir().unwrap();
    let environment = checkout.path().join("envs/linux");
    std::fs::create_dir_all(&environment).unwrap();
    std::fs::write(
        environment.join("Containerfile"),
        "FROM docker.io/library/alpine:3.20\n",
    )
    .unwrap();
    let expected = clusterflux_core::discover_environments(checkout.path())
        .unwrap()
        .into_iter()
        .find(|environment| environment.name == "linux")
        .unwrap()
        .digest;
    verify_environment_digest(checkout.path(), "linux", &expected).unwrap();

    std::fs::write(
        environment.join("Containerfile"),
        "FROM docker.io/library/alpine:3.21\n",
    )
    .unwrap();
    let error = verify_environment_digest(checkout.path(), "linux", &expected).unwrap_err();

    assert!(error.contains("does not match the bundle"));
    assert!(error.contains(expected.as_str()));
}

#[test]
fn configured_secret_values_are_redacted_before_guest_or_coordinator_logging() {
    assert!(is_secret_environment_name("API_TOKEN"));
    assert!(is_secret_environment_name("database_password"));
    assert!(!is_secret_environment_name("SOURCE_DATE_EPOCH"));
    assert_eq!(
        redact_configured_values(
            "token=correct-horse and again correct-horse".to_owned(),
            &["correct-horse".to_owned()],
        ),
        "token=[REDACTED] and again [REDACTED]"
    );
}

#[test]
fn native_command_requires_environment_and_network_grant() {
    let error = require_command_environment(None).unwrap_err();
    assert!(error.contains("explicit command-capable environment"));
    assert_eq!(require_command_environment(Some("linux")).unwrap(), "linux");

    authorize_command_network(&clusterflux_core::CommandNetworkPolicy::Disabled, false).unwrap();
    let error = authorize_command_network(&clusterflux_core::CommandNetworkPolicy::Enabled, false)
        .unwrap_err();
    assert!(error.contains("Network capability"));
}

#[test]
fn wasm_command_result_is_bounded_while_native_log_state_keeps_the_larger_tail() {
    let stdout = format!("old-prefix-{}-real-tail", "\u{0001}".repeat(96 * 1024));
    let output = CommandOutput {
        virtual_thread: TaskInstanceId::from("task"),
        status_code: Some(0),
        stdout: stdout.clone(),
        stderr: "compiler warning".repeat(8 * 1024),
        stdout_source_bytes: stdout.len() as u64,
        stderr_source_bytes: (16 * 8 * 1024) as u64,
        stdout_truncated: false,
        stderr_truncated: false,
        log_backpressured: false,
        staged_artifact: None,
    };
    let mut state = NativeCommandLogState::default();
    state.record(&output);
    let bounded = bounded_wasm_command_result(&output).unwrap();
    let encoded = serde_json::to_vec(&Ok::<_, String>(&bounded)).unwrap();

    assert!(encoded.len() <= clusterflux_core::MAX_WASM_TASK_ENVELOPE_BYTES);
    assert!(bounded.stdout.ends_with("real-tail"));
    assert!(bounded.stdout_truncated);
    assert_eq!(state.stdout, stdout);
    assert!(!state.stdout_truncated);
}

#[test]
fn native_command_log_snapshot_uses_exact_source_counts_and_latest_bounded_tail() {
    let mut state = NativeCommandLogState::default();
    let values = [
        "first-line\n".to_owned(),
        format!("{}latest-tail", "x".repeat(300 * 1024)),
    ];
    for value in &values {
        state.record(&CommandOutput {
            virtual_thread: TaskInstanceId::from("task"),
            status_code: Some(0),
            stdout: value.to_owned(),
            stderr: String::new(),
            stdout_source_bytes: value.len() as u64,
            stderr_source_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            log_backpressured: false,
            staged_artifact: None,
        });
    }
    let stdout_bytes = AtomicU64::new(912_345);
    let stderr_bytes = AtomicU64::new(12);
    let snapshot = state.snapshot(&stdout_bytes, &stderr_bytes);

    assert_eq!(snapshot.stdout_source_bytes, 912_345);
    assert_eq!(snapshot.stderr_source_bytes, 12);
    assert_eq!(snapshot.stdout.len(), DEFAULT_COMMAND_LOG_LIMIT_BYTES);
    assert!(snapshot.stdout.ends_with("latest-tail"));
    assert!(snapshot.stdout_truncated);
}

#[test]
fn task_secret_grant_expiry_is_checked_at_injection_boundary() {
    let grant = clusterflux_protocol::TaskSecretGrant {
        process: ProcessId::from("process"),
        task: TaskInstanceId::from("task"),
        secret_name: "TOKEN".to_owned(),
        value_base64: clusterflux_protocol::RedactedSecret::new("c2VjcmV0".to_owned()),
        expires_at_epoch_seconds: 50,
    };
    assert!(validate_task_secret_grant(&grant, "TOKEN", "process", "task", 49).is_ok());
    assert!(
        validate_task_secret_grant(&grant, "TOKEN", "process", "task", 50)
            .unwrap_err()
            .contains("expired")
    );
}
