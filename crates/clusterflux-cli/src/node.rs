use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clusterflux_core::{
    generate_ed25519_private_key, node_ed25519_public_key_from_private_key, sign_node_request,
    signed_request_payload_digest, Capability, Digest, EnvironmentBackend, NodeCapabilities,
    NodeId,
};
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};
use serde::Serialize;
use serde_json::{json, Value};

use crate::client::{authenticated_or_local_trusted_request, JsonLineSession};
use crate::config::{
    default_hosted_coordinator_endpoint, effective_scope_value, read_cli_session, StoredCliSession,
};
use crate::tools::{command_available, command_nonce, unix_timestamp_seconds};
use crate::{
    confirmation_required_report, AttachArgs, CliScopeArgs, NodeDoctorArgs, NodeEnrollArgs,
    NodeListArgs, NodeRevokeArgs, NodeStatusArgs,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct NodeAttachPlan {
    pub(crate) node: String,
    pub(crate) coordinator: Option<String>,
    pub(crate) capabilities: NodeCapabilities,
    pub(crate) detection: NodeAttachDetectionEvidence,
    pub(crate) grant_disclosures: Vec<CapabilityGrantDisclosure>,
    pub(crate) enrollment: Option<NodeEnrollmentPlan>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct NodeAttachReport {
    pub(crate) command: String,
    pub(crate) coordinator: String,
    pub(crate) tenant: String,
    pub(crate) project: String,
    pub(crate) node: String,
    pub(crate) plan: NodeAttachPlan,
    pub(crate) grant_disclosures: Vec<CapabilityGrantDisclosure>,
    pub(crate) boundary: NodeAttachBoundaryEvidence,
    pub(crate) coordinator_response: CoordinatorResponse,
    pub(crate) heartbeat_response: CoordinatorResponse,
    pub(crate) capability_response: CoordinatorResponse,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct NodeAttachBoundaryEvidence {
    pub(crate) cli_contacted_coordinator: bool,
    pub(crate) coordinator_address: String,
    pub(crate) used_enrollment_exchange: bool,
    pub(crate) coordinator_session_requests: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CapabilityGrantDisclosure {
    pub(crate) capability: Capability,
    pub(crate) grant: String,
    pub(crate) description: String,
    pub(crate) risk: String,
    pub(crate) coordinator_policy_limited: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct NodeAttachDetectionEvidence {
    pub(crate) auto_detected: bool,
    pub(crate) os: clusterflux_core::Os,
    pub(crate) arch: String,
    pub(crate) command_backend: String,
    pub(crate) command_backend_available: bool,
    pub(crate) container_backend: Option<String>,
    pub(crate) container_backend_reported: bool,
    pub(crate) container_backend_available: bool,
    pub(crate) source_provider_backends: Vec<SourceProviderBackendStatus>,
    pub(crate) manual_capability_overrides_allowed: bool,
    pub(crate) manual_capability_overrides: Vec<String>,
    pub(crate) recognized_capability_overrides: Vec<Capability>,
    pub(crate) unrecognized_capability_overrides: Vec<String>,
    pub(crate) os_arch_capabilities_require_manual_flags: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct SourceProviderBackendStatus {
    pub(crate) provider: String,
    pub(crate) detected: bool,
    pub(crate) available: bool,
    pub(crate) reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct NodeEnrollmentPlan {
    pub(crate) grant: String,
    pub(crate) public_key_fingerprint: Digest,
    pub(crate) exchanges_short_lived_grant_for_long_lived_node_identity: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct StoredNodeCredential {
    kind: String,
    node: String,
    private_key: String,
    public_key: String,
    credential_scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    coordinator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project: Option<String>,
}

pub(crate) fn node_enroll_report(args: NodeEnrollArgs, cwd: PathBuf) -> Result<Value> {
    let stored_session = read_cli_session(&cwd)?;
    let coordinator = args.scope.coordinator.clone().or_else(|| {
        stored_session
            .as_ref()
            .map(|session| session.coordinator.clone())
    });
    if let Some(coordinator) = &coordinator {
        let tenant = session_or_effective_scope_value(
            stored_session.as_ref(),
            &args.scope.tenant,
            |session| session.tenant.as_str(),
            "tenant",
        );
        let project = session_or_effective_scope_value(
            stored_session.as_ref(),
            &args.scope.project,
            |session| session.project.as_str(),
            "project",
        );
        let user = session_or_effective_scope_value(
            stored_session.as_ref(),
            &args.scope.user,
            |session| session.user.as_str(),
            "user",
        );
        let ttl_seconds = args.ttl_seconds;
        let mut session = JsonLineSession::connect(coordinator)?;
        let request = authenticated_or_local_trusted_request(
            coordinator,
            stored_session.as_ref(),
            CoordinatorRequest::CreateNodeEnrollmentGrant {
                tenant: tenant.clone(),
                project: project.clone(),
                actor_user: user.clone(),
                ttl_seconds,
            },
        )?;
        let response = session.request(request)?;
        let enrollment_grant =
            node_enrollment_grant_summary(&response, &tenant, &project, &user, ttl_seconds)?;
        return Ok(json!({
            "command": "node enroll",
            "status": "created",
            "coordinator": coordinator,
            "tenant": tenant,
            "project": project,
            "user": user,
            "external_website_required": false,
            "enrollment_grant": enrollment_grant,
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "node enroll",
        "status": "requires_coordinator",
        "external_website_required": false,
        "requested_ttl_seconds": args.ttl_seconds,
        "enrollment_grant": null,
        "reason": "enrollment grants are generated by the coordinator and cannot be planned client-side",
    }))
}

fn node_enrollment_grant_summary(
    response: &CoordinatorResponse,
    tenant: &str,
    project: &str,
    user: &str,
    ttl_seconds: u64,
) -> Result<Value> {
    let CoordinatorResponse::NodeEnrollmentGrantCreated {
        tenant: response_tenant,
        project: response_project,
        grant,
        scope,
        expires_at_epoch_seconds,
    } = response
    else {
        anyhow::bail!("coordinator returned an unexpected node-enrollment response");
    };
    if response_tenant.as_str() != tenant || response_project.as_str() != project {
        anyhow::bail!("coordinator enrollment grant scope does not match the request");
    }
    Ok(json!({
        "grant": grant,
        "tenant": response_tenant,
        "project": response_project,
        "user": user,
        "scope": scope,
        "ttl_seconds": ttl_seconds,
        "expires_at_epoch_seconds": expires_at_epoch_seconds,
        "short_lived": true,
        "exchange_for_persistent_node_identity": true,
        "node_credentials_separate_from_user_session": true,
    }))
}

pub(crate) fn node_list_report(args: NodeListArgs, cwd: PathBuf) -> Result<Value> {
    node_descriptors_report("node list", args.scope, None, cwd)
}

pub(crate) fn node_status_report(args: NodeStatusArgs, cwd: PathBuf) -> Result<Value> {
    node_descriptors_report("node status", args.scope, args.node, cwd)
}

pub(crate) fn node_doctor_report(args: NodeDoctorArgs, cwd: PathBuf) -> Result<Value> {
    use crate::guidance::{attach_guidance, GuidanceKind, GuidedCommand, OperationGuidance};

    let stored_session = read_cli_session(&cwd)?;
    let full = args.full;
    let selected_environment = args.environment.clone();
    let node = args.node.unwrap_or_else(default_node_id);
    let coordinator = args.scope.coordinator.clone().or_else(|| {
        stored_session
            .as_ref()
            .map(|session| session.coordinator.clone())
    });
    let tenant = session_or_effective_scope_value(
        stored_session.as_ref(),
        &args.scope.tenant,
        |session| session.tenant.as_str(),
        "tenant",
    );
    let project = session_or_effective_scope_value(
        stored_session.as_ref(),
        &args.scope.project,
        |session| session.project.as_str(),
        "project",
    );
    let user = session_or_effective_scope_value(
        stored_session.as_ref(),
        &args.scope.user,
        |session| session.user.as_str(),
        "user",
    );
    let local_identity =
        inspect_local_node_identity(&cwd, &node, coordinator.as_deref(), &tenant, &project);
    let remote = node_descriptors_report(
        "node doctor probe",
        args.scope,
        Some(node.clone()),
        cwd.clone(),
    );
    let (remote_report, mut machine_error) = match remote {
        Ok(report) => (Some(report), None),
        Err(error) => {
            let machine_error = crate::errors::cli_error_summary_from_error(&error);
            (None, Some(machine_error))
        }
    };
    let summary = remote_report
        .as_ref()
        .and_then(|report| report.pointer("/response/nodes"))
        .and_then(Value::as_array)
        .and_then(|nodes| {
            nodes
                .iter()
                .find(|candidate| candidate.get("id").and_then(Value::as_str) == Some(&node))
        })
        .cloned();
    let enrolled = summary.is_some();
    let online = summary
        .as_ref()
        .and_then(|summary| summary.get("online"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let container_backend = summary
        .as_ref()
        .and_then(|summary| summary.pointer("/capabilities/environment_backends"))
        .and_then(Value::as_array)
        .is_some_and(|backends| {
            backends
                .iter()
                .any(|backend| backend.as_str() == Some("Container"))
        });
    let compiler_status = summary
        .as_ref()
        .and_then(|summary| summary.get("automatic_workflow_compilation"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let full_runtime =
        full.then(|| windows_full_runtime_doctor(&cwd, selected_environment.as_deref()));
    if machine_error.is_none() {
        if let Some(runtime) = full_runtime.as_ref().filter(|runtime| !runtime.ready) {
            machine_error = Some(crate::errors::cli_error_summary_for_category(
                "environment",
                &format!(
                    "full Windows runtime doctor failed at {}: {}",
                    runtime.failure_layer.as_deref().unwrap_or("unknown"),
                    runtime.message
                ),
            ));
        }
    }
    let mut report = json!({
        "command": "node doctor",
        "coordinator": coordinator,
        "tenant": tenant,
        "project": project,
        "user": user,
        "node": node,
        "coordinator_reachable": remote_report.is_some(),
        "coordinator_identity_enrolled": enrolled,
        "coordinator_node": summary,
        "node_online": online,
        "container_backend_reported": container_backend,
        "automatic_workflow_compilation": compiler_status,
        "local_identity": local_identity,
        "local_capabilities": NodeCapabilities::detect_current(),
        "full_runtime": full_runtime,
        "read_only": !full,
        "coordinator_state_read_only": true,
        "machine_error": machine_error,
    });
    let guidance = if machine_error.is_some() {
        let mut command = vec!["clusterflux".to_owned(), "doctor".to_owned()];
        append_guidance_scope(
            &mut command,
            coordinator.as_deref(),
            &tenant,
            &project,
            &user,
        );
        OperationGuidance::recommended(GuidedCommand::new(
            GuidanceKind::Inspect,
            command,
            false,
            false,
        ))
        .build()?
    } else if !enrolled {
        let mut command = vec![
            "clusterflux".to_owned(),
            "node".to_owned(),
            "enroll".to_owned(),
        ];
        append_guidance_scope(
            &mut command,
            coordinator.as_deref(),
            &tenant,
            &project,
            &user,
        );
        OperationGuidance::recommended(GuidedCommand::new(
            GuidanceKind::Configure,
            command,
            true,
            false,
        ))
        .build()?
    } else if !online {
        let mut command = vec![
            "clusterflux".to_owned(),
            "wait".to_owned(),
            "node".to_owned(),
            "--node".to_owned(),
            node.clone(),
            "--for".to_owned(),
            "ready".to_owned(),
            "--timeout".to_owned(),
            "5m".to_owned(),
        ];
        append_guidance_scope(
            &mut command,
            coordinator.as_deref(),
            &tenant,
            &project,
            &user,
        );
        OperationGuidance::recommended(GuidedCommand::new(
            GuidanceKind::Wait,
            command,
            false,
            false,
        ))
        .build()?
    } else {
        OperationGuidance::no_safe_action(
            "node identity and runtime are ready; no follow-up is required",
        )
        .build()?
    };
    attach_guidance(&mut report, guidance)?;
    Ok(report)
}

#[derive(Clone, Debug, Serialize)]
struct WindowsRuntimeDoctorReport {
    ready: bool,
    failure_layer: Option<String>,
    message: String,
    environment: Option<String>,
    image: Option<String>,
    checks: Vec<WindowsRuntimeDoctorCheck>,
    bounded: bool,
    mutates_runtime_temporarily: bool,
    cleanup_attempted: bool,
}

#[derive(Clone, Debug, Serialize)]
struct WindowsRuntimeDoctorCheck {
    layer: String,
    passed: bool,
    detail: String,
}

impl WindowsRuntimeDoctorReport {
    fn failed(
        layer: impl Into<String>,
        message: impl Into<String>,
        environment: Option<String>,
        image: Option<String>,
        checks: Vec<WindowsRuntimeDoctorCheck>,
    ) -> Self {
        let layer = layer.into();
        let message = message.into();
        Self {
            ready: false,
            failure_layer: Some(layer),
            message,
            environment,
            image,
            checks,
            bounded: true,
            mutates_runtime_temporarily: true,
            cleanup_attempted: true,
        }
    }
}

#[cfg(not(windows))]
fn windows_full_runtime_doctor(
    _project_root: &Path,
    environment: Option<&str>,
) -> WindowsRuntimeDoctorReport {
    WindowsRuntimeDoctorReport::failed(
        "platform",
        "full Windows runtime qualification must run on the Windows node",
        environment.map(str::to_owned),
        None,
        Vec::new(),
    )
}

#[cfg(windows)]
fn windows_full_runtime_doctor(
    project_root: &Path,
    requested_environment: Option<&str>,
) -> WindowsRuntimeDoctorReport {
    use std::process::Command;
    use std::time::Duration;

    let mut checks = Vec::new();
    let readiness = clusterflux_core::probe_containerd_nerdctl_readiness();
    checks.push(WindowsRuntimeDoctorCheck {
        layer: "containerd_connectivity".to_owned(),
        passed: readiness.ready,
        detail: readiness.message.clone(),
    });
    if !readiness.ready {
        return WindowsRuntimeDoctorReport::failed(
            readiness
                .failure_layer
                .unwrap_or_else(|| "containerd_connectivity".to_owned()),
            readiness.message,
            requested_environment.map(str::to_owned),
            None,
            checks,
        );
    }

    let version = match run_bounded_doctor_command(
        Command::new("nerdctl").args(["version", "--format", "{{json .}}"]),
        Duration::from_secs(5),
    ) {
        Ok(output) => output,
        Err(error) => {
            return WindowsRuntimeDoctorReport::failed(
                "nerdctl_compatibility",
                error,
                requested_environment.map(str::to_owned),
                None,
                checks,
            )
        }
    };
    let version_json: Value = match serde_json::from_slice(&version.stdout) {
        Ok(value) => value,
        Err(error) => {
            return WindowsRuntimeDoctorReport::failed(
                "nerdctl_compatibility",
                format!("parse nerdctl version JSON: {error}"),
                requested_environment.map(str::to_owned),
                None,
                checks,
            )
        }
    };
    let client_windows =
        version_json.pointer("/Client/Os").and_then(Value::as_str) == Some("windows");
    let server_version = version_json
        .pointer("/Server/Components/0/Version")
        .and_then(Value::as_str)
        .filter(|version| !version.trim().is_empty());
    if !client_windows || server_version.is_none() {
        return WindowsRuntimeDoctorReport::failed(
            "nerdctl_compatibility",
            "nerdctl did not report a Windows client and reachable containerd server",
            requested_environment.map(str::to_owned),
            None,
            checks,
        );
    }
    checks.push(WindowsRuntimeDoctorCheck {
        layer: "nerdctl_compatibility".to_owned(),
        passed: true,
        detail: format!(
            "Windows nerdctl client reached containerd {}",
            server_version.unwrap_or_default()
        ),
    });

    let network = match run_bounded_doctor_command(
        Command::new("nerdctl").args(["network", "inspect", "nat"]),
        Duration::from_secs(5),
    ) {
        Ok(output) => output,
        Err(error) => {
            return WindowsRuntimeDoctorReport::failed(
                "cni_network",
                error,
                requested_environment.map(str::to_owned),
                None,
                checks,
            )
        }
    };
    if serde_json::from_slice::<Value>(&network.stdout).is_err() {
        return WindowsRuntimeDoctorReport::failed(
            "cni_network",
            "nerdctl returned malformed data for the Windows nat network",
            requested_environment.map(str::to_owned),
            None,
            checks,
        );
    }
    checks.push(WindowsRuntimeDoctorCheck {
        layer: "cni_network".to_owned(),
        passed: true,
        detail: "the Windows nat CNI network is configured".to_owned(),
    });

    let environments = match clusterflux_core::discover_environments(project_root) {
        Ok(environments) => environments,
        Err(error) => {
            return WindowsRuntimeDoctorReport::failed(
                "environment_discovery",
                error.to_string(),
                requested_environment.map(str::to_owned),
                None,
                checks,
            )
        }
    };
    let mut candidates = environments
        .into_iter()
        .filter(|environment| environment.requirements.os == Some(clusterflux_core::Os::Windows))
        .filter(|environment| {
            requested_environment.is_none_or(|requested| environment.name == requested)
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        let message = match requested_environment {
            Some(requested) => format!(
                "expected exactly one Windows environment named `{requested}`, found {}",
                candidates.len()
            ),
            None => format!(
                "expected exactly one Windows environment; found {} (select one with --environment)",
                candidates.len()
            ),
        };
        return WindowsRuntimeDoctorReport::failed(
            "environment_discovery",
            message,
            requested_environment.map(str::to_owned),
            None,
            checks,
        );
    }
    let environment = candidates.remove(0);
    let image = clusterflux_core::environment_image_tag(&environment);
    if let Err(error) = run_bounded_doctor_command(
        Command::new("nerdctl").args(["image", "inspect", &image]),
        Duration::from_secs(10),
    ) {
        return WindowsRuntimeDoctorReport::failed(
            "environment_image",
            format!(
                "prebuilt environment image `{image}` is unavailable: {error}; run clusterflux-environment-setup --project-root {} --name {}",
                project_root.display(),
                environment.name
            ),
            Some(environment.name),
            Some(image),
            checks,
        );
    }
    checks.push(WindowsRuntimeDoctorCheck {
        layer: "environment_image".to_owned(),
        passed: true,
        detail: format!("prebuilt immutable image `{image}` is present"),
    });

    let staging = match tempfile::Builder::new()
        .prefix("clusterflux-node-doctor-")
        .tempdir()
    {
        Ok(staging) => staging,
        Err(error) => {
            return WindowsRuntimeDoctorReport::failed(
                "mount_staging",
                format!("create doctor staging directory: {error}"),
                Some(environment.name),
                Some(image),
                checks,
            )
        }
    };
    let source = staging.path().join("source");
    let output = staging.path().join("output");
    if let Err(error) = std::fs::create_dir_all(&source)
        .and_then(|_| std::fs::create_dir_all(&output))
        .and_then(|_| std::fs::write(source.join("probe.txt"), b"clusterflux-doctor\r\n"))
    {
        return WindowsRuntimeDoctorReport::failed(
            "mount_staging",
            format!("prepare doctor source/output mounts: {error}"),
            Some(environment.name),
            Some(image),
            checks,
        );
    }
    for (path, rights) in [(&source, "RX"), (&output, "M")] {
        let grant = format!("*S-1-5-11:(OI)(CI){rights}");
        if let Err(error) = run_bounded_doctor_command(
            Command::new("icacls.exe")
                .arg(path)
                .args(["/grant", &grant, "/T", "/C", "/Q"]),
            Duration::from_secs(10),
        ) {
            return WindowsRuntimeDoctorReport::failed(
                "mount_acl",
                error,
                Some(environment.name),
                Some(image),
                checks,
            );
        }
    }

    let source_mount = format!(r"{}:C:\workspace:ro", source.display());
    let output_mount = format!(r"{}:C:\clusterflux\output", output.display());
    let no_op = run_bounded_doctor_command(
        Command::new("nerdctl").args([
            "run",
            "--rm",
            "--pull=never",
            "--isolation=process",
            "--network=none",
            "--volume",
            &source_mount,
            "--volume",
            &output_mount,
            &image,
            "cmd.exe",
            "/D",
            "/S",
            "/C",
            r#"type C:\workspace\probe.txt > C:\clusterflux\output\probe.txt"#,
        ]),
        Duration::from_secs(30),
    );
    if let Err(error) = no_op {
        return WindowsRuntimeDoctorReport::failed(
            "process_isolation_and_mounts",
            error,
            Some(environment.name),
            Some(image),
            checks,
        );
    }
    let staged_probe = std::fs::read(output.join("probe.txt"));
    if !matches!(staged_probe, Ok(ref bytes) if bytes == b"clusterflux-doctor\r\n") {
        return WindowsRuntimeDoctorReport::failed(
            "source_output_mounts",
            "process-isolated container did not copy the expected source bytes into the output mount",
            Some(environment.name),
            Some(image),
            checks,
        );
    }
    checks.push(WindowsRuntimeDoctorCheck {
        layer: "process_isolation_and_mounts".to_owned(),
        passed: true,
        detail: "bounded process-isolated no-op read the source mount and wrote the output mount"
            .to_owned(),
    });

    let container_name = command_nonce("clusterflux-doctor");
    let mut cleanup = WindowsDoctorContainerCleanup::new(container_name.clone());
    if let Err(error) = run_bounded_doctor_command(
        Command::new("nerdctl").args([
            "run",
            "--detach",
            "--name",
            &container_name,
            "--pull=never",
            "--isolation=process",
            "--network=none",
            &image,
            "cmd.exe",
            "/D",
            "/S",
            "/C",
            "ping -n 30 127.0.0.1 >NUL",
        ]),
        Duration::from_secs(20),
    ) {
        return WindowsRuntimeDoctorReport::failed(
            "pause_unpause",
            error,
            Some(environment.name),
            Some(image),
            checks,
        );
    }
    cleanup.created = true;
    let root_process_id = match doctor_windows_container_entry_process_id(&container_name) {
        Ok(process_id) => process_id,
        Err(error) => {
            return WindowsRuntimeDoctorReport::failed(
                "pause_unpause",
                error,
                Some(environment.name),
                Some(image),
                checks,
            );
        }
    };
    let mut suspended = clusterflux_core::SuspendedWindowsProcesses::new();
    let mut stable = false;
    for _ in 0..8 {
        match suspended.suspend_process_tree(root_process_id) {
            Ok(0) => {
                stable = true;
                break;
            }
            Ok(_) => {}
            Err(error) => {
                return WindowsRuntimeDoctorReport::failed(
                    "pause_unpause",
                    error,
                    Some(environment.name),
                    Some(image),
                    checks,
                );
            }
        }
    }
    if !stable {
        return WindowsRuntimeDoctorReport::failed(
            "pause_unpause",
            "Windows container did not reach a stable all-thread suspension after 8 passes",
            Some(environment.name),
            Some(image),
            checks,
        );
    }
    let suspended_threads = suspended.suspended_thread_count();
    if let Err(error) = suspended.resume() {
        return WindowsRuntimeDoctorReport::failed(
            "pause_unpause",
            error,
            Some(environment.name),
            Some(image),
            checks,
        );
    }
    cleanup.remove_now();
    checks.push(WindowsRuntimeDoctorCheck {
        layer: "pause_unpause".to_owned(),
        passed: true,
        detail: format!(
            "process-isolated task entry process and descendants suspended and resumed {suspended_threads} threads, then the container was removed by exact name"
        ),
    });

    WindowsRuntimeDoctorReport {
        ready: true,
        failure_layer: None,
        message: "full Windows container runtime doctor passed".to_owned(),
        environment: Some(environment.name),
        image: Some(image),
        checks,
        bounded: true,
        mutates_runtime_temporarily: true,
        cleanup_attempted: true,
    }
}

#[cfg(windows)]
fn doctor_windows_container_entry_process_id(container: &str) -> std::result::Result<u32, String> {
    let output = run_bounded_doctor_command(
        std::process::Command::new("nerdctl").args([
            "inspect",
            "--format",
            "{{.State.Pid}}",
            container,
        ]),
        std::time::Duration::from_secs(10),
    )?;
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    value
        .parse::<u32>()
        .map_err(|_| format!("nerdctl returned invalid Windows task entry PID `{value}`"))
}

#[cfg(windows)]
struct WindowsDoctorContainerCleanup {
    name: String,
    created: bool,
}

#[cfg(windows)]
impl WindowsDoctorContainerCleanup {
    fn new(name: String) -> Self {
        Self {
            name,
            created: false,
        }
    }

    fn remove_now(&mut self) {
        if !self.created {
            return;
        }
        let _ = run_bounded_doctor_command(
            std::process::Command::new("nerdctl").args(["rm", "--force", &self.name]),
            std::time::Duration::from_secs(10),
        );
        self.created = false;
    }
}

#[cfg(windows)]
impl Drop for WindowsDoctorContainerCleanup {
    fn drop(&mut self) {
        self.remove_now();
    }
}

#[cfg(windows)]
fn run_bounded_doctor_command(
    command: &mut std::process::Command,
    timeout: std::time::Duration,
) -> std::result::Result<std::process::Output, String> {
    use std::process::Stdio;
    use wait_timeout::ChildExt;

    const MAX_OUTPUT_BYTES: usize = 256 * 1024;
    let description = format!("{command:?}");
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start {description}: {error}"))?;
    match child
        .wait_timeout(timeout)
        .map_err(|error| format!("wait for {description}: {error}"))?
    {
        Some(_) => {}
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "{description} did not complete within {} seconds",
                timeout.as_secs()
            ));
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("collect {description} output: {error}"))?;
    if output.stdout.len() > MAX_OUTPUT_BYTES || output.stderr.len() > MAX_OUTPUT_BYTES {
        return Err(format!("{description} output exceeded 256 KiB"));
    }
    if !output.status.success() {
        return Err(format!(
            "{description} failed with status {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output)
}

fn append_guidance_scope(
    command: &mut Vec<String>,
    coordinator: Option<&str>,
    tenant: &str,
    project: &str,
    user: &str,
) {
    if let Some(coordinator) = coordinator {
        command.extend(["--coordinator".to_owned(), coordinator.to_owned()]);
    }
    command.extend([
        "--tenant".to_owned(),
        tenant.to_owned(),
        "--project-id".to_owned(),
        project.to_owned(),
        "--user".to_owned(),
        user.to_owned(),
    ]);
}

fn inspect_local_node_identity(
    project_root: &Path,
    node: &str,
    coordinator: Option<&str>,
    tenant: &str,
    project: &str,
) -> Value {
    let file = local_node_credential_file(project_root, node);
    let result = (|| -> Result<Value> {
        if !credential_file_exists_without_symlink(&file)? {
            return Ok(json!({
                "present": false,
                "valid": false,
                "file": file,
                "scope_matches": false,
            }));
        }
        let bytes =
            std::fs::read(&file).with_context(|| format!("failed to read {}", file.display()))?;
        let credential: StoredNodeCredential = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse {}", file.display()))?;
        if credential.node != node {
            anyhow::bail!("stored identity belongs to node `{}`", credential.node);
        }
        let public_key = node_ed25519_public_key_from_private_key(&credential.private_key)
            .map_err(anyhow::Error::msg)?;
        if public_key != credential.public_key {
            anyhow::bail!("stored identity keypair does not match");
        }
        let scope_matches = credential.coordinator.as_deref() == coordinator
            && credential.tenant.as_deref() == Some(tenant)
            && credential.project.as_deref() == Some(project);
        Ok(json!({
            "present": true,
            "valid": true,
            "file": file,
            "scope_matches": scope_matches,
            "stored_coordinator": credential.coordinator,
            "stored_tenant": credential.tenant,
            "stored_project": credential.project,
            "private_key_exposed": false,
        }))
    })();
    result.unwrap_or_else(|error| {
        json!({
            "present": file.exists(),
            "valid": false,
            "file": file,
            "scope_matches": false,
            "error": error.to_string(),
            "private_key_exposed": false,
        })
    })
}

fn node_descriptors_report(
    command: &str,
    scope: CliScopeArgs,
    node: Option<String>,
    cwd: PathBuf,
) -> Result<Value> {
    let stored_session = read_cli_session(&cwd)?;
    let coordinator = scope.coordinator.clone().or_else(|| {
        stored_session
            .as_ref()
            .map(|session| session.coordinator.clone())
    });
    if let Some(coordinator) = &coordinator {
        let tenant = session_or_effective_scope_value(
            stored_session.as_ref(),
            &scope.tenant,
            |session| session.tenant.as_str(),
            "tenant",
        );
        let project = session_or_effective_scope_value(
            stored_session.as_ref(),
            &scope.project,
            |session| session.project.as_str(),
            "project",
        );
        let user = session_or_effective_scope_value(
            stored_session.as_ref(),
            &scope.user,
            |session| session.user.as_str(),
            "user",
        );
        let mut session = JsonLineSession::connect(coordinator)?;
        let request = authenticated_or_local_trusted_request(
            coordinator,
            stored_session.as_ref(),
            CoordinatorRequest::ListNodeSummaries {
                tenant: tenant.clone(),
                project: project.clone(),
                actor_user: user.clone(),
                cursor: None,
                limit: 100,
            },
        )?;
        let response = session.request(request)?;
        if !matches!(&response, CoordinatorResponse::NodeSummaries { .. }) {
            anyhow::bail!("coordinator returned an unexpected node-list response");
        }
        return Ok(json!({
            "command": command,
            "coordinator": coordinator,
            "node": node,
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": command,
        "status": "local_capability_snapshot",
        "node": node.unwrap_or_else(default_node_id),
        "capabilities": NodeCapabilities::detect_current(),
    }))
}

pub(crate) fn node_revoke_report(args: NodeRevokeArgs, cwd: PathBuf) -> Result<Value> {
    if !args.yes {
        return Ok(confirmation_required_report(
            "node revoke",
            "revoke_node_credential",
            json!({
                "coordinator": args.scope.coordinator,
                "tenant": args.scope.tenant,
                "project": args.scope.project,
                "user": args.scope.user,
                "node": args.node,
            }),
            format!("clusterflux node revoke --node {} --yes", args.node),
        ));
    }
    let stored_session = read_cli_session(&cwd)?;
    let coordinator = args.scope.coordinator.clone().or_else(|| {
        stored_session
            .as_ref()
            .map(|session| session.coordinator.clone())
    });
    if let Some(coordinator) = &coordinator {
        let tenant = session_or_effective_scope_value(
            stored_session.as_ref(),
            &args.scope.tenant,
            |session| session.tenant.as_str(),
            "tenant",
        );
        let project = session_or_effective_scope_value(
            stored_session.as_ref(),
            &args.scope.project,
            |session| session.project.as_str(),
            "project",
        );
        let user = session_or_effective_scope_value(
            stored_session.as_ref(),
            &args.scope.user,
            |session| session.user.as_str(),
            "user",
        );
        let node = args.node.clone();
        let mut session = JsonLineSession::connect(coordinator)?;
        let request = authenticated_or_local_trusted_request(
            coordinator,
            stored_session.as_ref(),
            CoordinatorRequest::RevokeNodeCredential {
                tenant: tenant.clone(),
                project: project.clone(),
                actor_user: user.clone(),
                node: node.clone(),
            },
        )?;
        let response = session.request(request)?;
        let (descriptor_removed, queued_assignments_removed) = match &response {
            CoordinatorResponse::NodeCredentialRevoked {
                descriptor_removed,
                queued_assignments_removed,
                ..
            } => (*descriptor_removed, *queued_assignments_removed),
            _ => anyhow::bail!("coordinator returned an unexpected node-revoke response"),
        };
        return Ok(json!({
            "command": "node revoke",
            "coordinator": coordinator,
            "requires_confirmation": !args.yes,
            "tenant": tenant,
            "project": project,
            "user": user,
            "node": node,
            "credential_revoked": true,
            "descriptor_removed": descriptor_removed,
            "queued_assignments_removed": queued_assignments_removed,
            "node_credentials_separate_from_user_session": true,
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "node revoke",
        "status": "requires_coordinator",
        "requires_confirmation": !args.yes,
        "node": args.node,
    }))
}

fn session_or_effective_scope_value(
    stored_session: Option<&StoredCliSession>,
    cli_value: &str,
    session_value: impl FnOnce(&StoredCliSession) -> &str,
    default_value: &str,
) -> String {
    if let Some(session) = stored_session.filter(|session| session.session_secret.is_some()) {
        session_value(session).to_owned()
    } else {
        effective_scope_value(cli_value, stored_session.map(session_value), default_value)
    }
}

pub(crate) fn attach_plan(args: AttachArgs) -> NodeAttachPlan {
    attach_plan_with_capabilities(args, NodeCapabilities::detect_current())
}

pub(crate) fn attach_plan_with_capabilities(
    args: AttachArgs,
    mut capabilities: NodeCapabilities,
) -> NodeAttachPlan {
    let mut recognized_capability_overrides = Vec::new();
    let mut unrecognized_capability_overrides = Vec::new();
    for cap in &args.caps {
        if let Some(parsed) = parse_capability(cap) {
            recognized_capability_overrides.push(parsed.clone());
            capabilities.capabilities.insert(parsed);
        } else {
            unrecognized_capability_overrides.push(cap.clone());
        }
    }
    recognized_capability_overrides.sort();
    recognized_capability_overrides.dedup();
    let node = args.node.unwrap_or_else(default_node_id);
    let public_key = args
        .public_key
        .unwrap_or_else(|| default_node_public_key_for_plan(&node));
    let enrollment = args.enrollment_grant.map(|grant| NodeEnrollmentPlan {
        grant,
        public_key_fingerprint: Digest::sha256(public_key),
        exchanges_short_lived_grant_for_long_lived_node_identity: true,
    });
    let detection = node_attach_detection_evidence(
        &capabilities,
        args.caps,
        recognized_capability_overrides,
        unrecognized_capability_overrides,
    );
    let grant_disclosures = capability_grant_disclosures(&capabilities);

    NodeAttachPlan {
        node,
        coordinator: args.coordinator,
        capabilities,
        detection,
        grant_disclosures,
        enrollment,
    }
}

fn node_attach_detection_evidence(
    capabilities: &NodeCapabilities,
    manual_capability_overrides: Vec<String>,
    recognized_capability_overrides: Vec<Capability>,
    unrecognized_capability_overrides: Vec<String>,
) -> NodeAttachDetectionEvidence {
    let command_backend_available = capabilities.capabilities.contains(&Capability::Command);
    let container_backend_reported = capabilities
        .environment_backends
        .contains(&EnvironmentBackend::Container);
    let (container_backend, container_backend_available) = if capabilities
        .capabilities
        .contains(&Capability::RootlessPodman)
    {
        (
            Some("rootless-podman".to_owned()),
            command_available("podman"),
        )
    } else if capabilities
        .capabilities
        .contains(&Capability::ContainerdNerdctl)
    {
        (
            Some("containerd-nerdctl".to_owned()),
            command_available("nerdctl"),
        )
    } else {
        (None, false)
    };

    NodeAttachDetectionEvidence {
        auto_detected: true,
        os: capabilities.os.clone(),
        arch: capabilities.arch.clone(),
        command_backend: if command_backend_available {
            "container-command".to_owned()
        } else {
            "unavailable".to_owned()
        },
        command_backend_available,
        container_backend,
        container_backend_reported,
        container_backend_available,
        source_provider_backends: source_provider_backend_statuses(capabilities),
        manual_capability_overrides_allowed: true,
        manual_capability_overrides,
        recognized_capability_overrides,
        unrecognized_capability_overrides,
        os_arch_capabilities_require_manual_flags: false,
    }
}

fn source_provider_backend_statuses(
    capabilities: &NodeCapabilities,
) -> Vec<SourceProviderBackendStatus> {
    let mut statuses = BTreeMap::new();
    for provider in &capabilities.source_providers {
        let available = match provider.as_str() {
            "filesystem" => capabilities
                .capabilities
                .contains(&Capability::SourceFilesystem),
            "git" => command_available("git"),
            _ => true,
        };
        statuses.insert(
            provider.clone(),
            SourceProviderBackendStatus {
                provider: provider.clone(),
                detected: true,
                available,
                reason: if available {
                    "detected by local node capability probe".to_owned()
                } else {
                    format!(
                        "source provider `{provider}` was detected but its local helper is missing"
                    )
                },
            },
        );
    }
    statuses.into_values().collect()
}

fn capability_grant_disclosures(capabilities: &NodeCapabilities) -> Vec<CapabilityGrantDisclosure> {
    let mut disclosures = Vec::new();
    let mut push = |capability: Capability, grant: &str, description: &str, risk: &str| {
        if capabilities.capabilities.contains(&capability) {
            disclosures.push(CapabilityGrantDisclosure {
                capability,
                grant: grant.to_owned(),
                description: description.to_owned(),
                risk: risk.to_owned(),
                coordinator_policy_limited: true,
            });
        }
    };

    push(
        Capability::Command,
        "container_command_execution",
        "placed tasks may run commands in declared container environments on this node",
        "container execution under the node account",
    );
    push(
        Capability::WindowsCommandDev,
        "native_command_execution",
        "placed tasks may run Windows developer commands on this node",
        "local process execution under the node account",
    );
    push(
        Capability::SourceFilesystem,
        "source_access",
        "placed tasks may read the local project/source checkout exposed by this node",
        "broad local source visibility",
    );
    push(
        Capability::SourceGit,
        "source_access",
        "placed tasks may use Git-backed source access exposed by this node",
        "source-provider visibility",
    );
    push(
        Capability::Network,
        "network_access",
        "placed tasks may use outbound network access from this node",
        "network egress from the node environment",
    );
    push(
        Capability::HostFilesystem,
        "host_filesystem_access",
        "placed tasks may access configured host filesystem mounts",
        "host file visibility outside the project checkout",
    );
    push(
        Capability::Secrets,
        "secret_access",
        "placed tasks may receive configured secret material",
        "secret exposure to authorized task code",
    );
    push(
        Capability::InboundPorts,
        "inbound_ports",
        "placed tasks may expose inbound ports from this node",
        "network service exposure from the node environment",
    );
    push(
        Capability::ArbitrarySyscalls,
        "arbitrary_syscalls",
        "placed tasks may use broader host syscall surface",
        "reduced host isolation",
    );

    disclosures.sort_by(|left, right| {
        left.grant
            .cmp(&right.grant)
            .then_with(|| left.capability.cmp(&right.capability))
    });
    disclosures
}

pub(crate) fn execute_node_attach(args: AttachArgs, cwd: &Path) -> Result<NodeAttachReport> {
    let stored_session = read_cli_session(cwd)?;
    let coordinator = args
        .coordinator
        .clone()
        .or_else(|| {
            stored_session
                .as_ref()
                .map(|session| session.coordinator.clone())
        })
        .unwrap_or_else(default_hosted_coordinator_endpoint);
    if args.tenant != "tenant"
        && stored_session
            .as_ref()
            .filter(|session| session.session_secret.is_some())
            .is_some_and(|session| session.tenant != args.tenant)
    {
        let authenticated_tenant = &stored_session
            .as_ref()
            .expect("checked stored session")
            .tenant;
        anyhow::bail!(
            "--tenant `{}` conflicts with the authenticated tenant `{authenticated_tenant}`; omit --tenant to use the authenticated scope",
            args.tenant
        );
    }
    let tenant = session_or_effective_scope_value(
        stored_session.as_ref(),
        &args.tenant,
        |session| session.tenant.as_str(),
        "tenant",
    );
    let project = session_or_effective_scope_value(
        stored_session.as_ref(),
        &args.project,
        |session| session.project.as_str(),
        "project",
    );
    let node = args.node.clone().unwrap_or_else(default_node_id);
    let node_private_key = node_private_key_for_attach(&node, cwd)?;
    let derived_public_key =
        node_ed25519_public_key_from_private_key(&node_private_key).map_err(anyhow::Error::msg)?;
    let public_key = args
        .public_key
        .clone()
        .unwrap_or(derived_public_key.clone());
    if public_key != derived_public_key {
        anyhow::bail!(
            "node attach --public-key must match CLUSTERFLUX_NODE_PRIVATE_KEY or the stored local node credential"
        );
    }
    let mut plan = attach_plan(args);
    plan.coordinator = Some(coordinator.clone());
    if let Some(enrollment) = &mut plan.enrollment {
        enrollment.public_key_fingerprint = Digest::sha256(&public_key);
    }

    let mut session = JsonLineSession::connect(&coordinator)?;
    let used_enrollment_exchange = plan.enrollment.is_some();
    let coordinator_response = if let Some(enrollment) = &plan.enrollment {
        session.request(CoordinatorRequest::ExchangeNodeEnrollmentGrant {
            tenant: tenant.clone(),
            project: project.clone(),
            node: node.clone(),
            public_key: public_key.clone(),
            enrollment_grant: enrollment.grant.clone(),
        })?
    } else {
        session.request(CoordinatorRequest::AttachNode {
            tenant: tenant.clone(),
            project: project.clone(),
            node: node.clone(),
            public_key: public_key.clone(),
        })?
    };
    let identity_accepted = if used_enrollment_exchange {
        matches!(
            &coordinator_response,
            CoordinatorResponse::NodeEnrollmentExchanged { .. }
        )
    } else {
        matches!(
            &coordinator_response,
            CoordinatorResponse::NodeAttached { .. }
        )
    };
    if !identity_accepted {
        anyhow::bail!("coordinator returned an unexpected node-identity response");
    }
    persist_node_credential_scope(cwd, &node, &coordinator, &tenant, &project)?;
    let heartbeat_request = CoordinatorRequest::NodeHeartbeat {
        tenant: tenant.clone(),
        project: project.clone(),
        node: plan.node.clone(),
        node_signature: None,
    };
    let heartbeat_payload = serde_json::to_value(&heartbeat_request)?;
    let heartbeat_signature = sign_node_request(
        &node_private_key,
        &NodeId::from(plan.node.as_str()),
        "node_heartbeat",
        &signed_request_payload_digest(&heartbeat_payload),
        command_nonce("node-heartbeat"),
        unix_timestamp_seconds(),
    )
    .map_err(anyhow::Error::msg)?;
    let heartbeat_request = CoordinatorRequest::NodeHeartbeat {
        tenant: tenant.clone(),
        project: project.clone(),
        node: plan.node.clone(),
        node_signature: Some(heartbeat_signature),
    };
    let heartbeat_response = session.request(heartbeat_request)?;
    if !matches!(
        &heartbeat_response,
        CoordinatorResponse::NodeHeartbeat { .. }
    ) {
        anyhow::bail!("coordinator returned an unexpected node-heartbeat response");
    }
    let capability_response = session.request(signed_node_request(
        &node_private_key,
        &plan.node,
        "report_node_capabilities",
        CoordinatorRequest::ReportNodeCapabilities {
            tenant: tenant.clone(),
            project: project.clone(),
            node: plan.node.clone(),
            capabilities: plan.capabilities.clone(),
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: false,
        },
    )?)?;
    if !matches!(
        &capability_response,
        CoordinatorResponse::NodeCapabilitiesRecorded { .. }
    ) {
        anyhow::bail!("coordinator returned an unexpected node-capability response");
    }

    Ok(NodeAttachReport {
        command: "node attach".to_owned(),
        coordinator: coordinator.clone(),
        tenant,
        project,
        node: plan.node.clone(),
        grant_disclosures: plan.grant_disclosures.clone(),
        plan,
        boundary: NodeAttachBoundaryEvidence {
            cli_contacted_coordinator: true,
            coordinator_address: coordinator,
            used_enrollment_exchange,
            coordinator_session_requests: session.requests(),
        },
        coordinator_response,
        heartbeat_response,
        capability_response,
    })
}

fn node_private_key_for_attach(node: &str, project_root: &Path) -> Result<String> {
    if let Ok(private_key) = std::env::var("CLUSTERFLUX_NODE_PRIVATE_KEY") {
        return Ok(private_key);
    }
    load_or_create_local_node_credential(project_root, node)
}

pub(crate) fn load_or_create_local_node_credential(project: &Path, node: &str) -> Result<String> {
    let file = local_node_credential_file(project, node);
    if credential_file_exists_without_symlink(&file)? {
        let bytes =
            std::fs::read(&file).with_context(|| format!("failed to read {}", file.display()))?;
        let credential: StoredNodeCredential = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse {}", file.display()))?;
        if credential.node != node {
            anyhow::bail!(
                "stored node credential {} belongs to node `{}` instead of `{}`",
                file.display(),
                credential.node,
                node
            );
        }
        let public_key = node_ed25519_public_key_from_private_key(&credential.private_key)
            .map_err(anyhow::Error::msg)?;
        if public_key != credential.public_key {
            anyhow::bail!(
                "stored node credential {} has a public key that does not match its private key",
                file.display()
            );
        }
        return Ok(credential.private_key);
    }

    let private_key = generate_ed25519_private_key().map_err(anyhow::Error::msg)?;
    let public_key =
        node_ed25519_public_key_from_private_key(&private_key).map_err(anyhow::Error::msg)?;
    let credential = StoredNodeCredential {
        kind: "clusterflux_node_credential".to_owned(),
        node: node.to_owned(),
        private_key: private_key.clone(),
        public_key,
        credential_scope: "local_project_node_identity".to_owned(),
        coordinator: None,
        tenant: None,
        project: None,
    };
    persist_node_credential(&file, &credential)?;
    Ok(private_key)
}

fn persist_node_credential_scope(
    project_root: &Path,
    node: &str,
    coordinator: &str,
    tenant: &str,
    project: &str,
) -> Result<()> {
    use std::io::Write;

    let file = local_node_credential_file(project_root, node);
    if !credential_file_exists_without_symlink(&file)? {
        return Ok(());
    }
    let bytes =
        std::fs::read(&file).with_context(|| format!("failed to read {}", file.display()))?;
    let mut credential: StoredNodeCredential = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", file.display()))?;
    credential.coordinator = Some(coordinator.to_owned());
    credential.tenant = Some(tenant.to_owned());
    credential.project = Some(project.to_owned());
    let parent = file
        .parent()
        .with_context(|| format!("node credential path {} has no parent", file.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "failed to create temporary credential in {}",
            parent.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(&serde_json::to_vec_pretty(&credential)?)?;
    temporary.as_file().sync_all()?;
    temporary.persist(&file).map_err(|error| {
        anyhow::anyhow!(
            "failed to update node credential scope {}: {}",
            file.display(),
            error.error
        )
    })?;
    Ok(())
}

fn credential_file_exists_without_symlink(file: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(file) {
        Ok(metadata) if metadata.file_type().is_symlink() => anyhow::bail!(
            "refusing to read node credential through symbolic link {}",
            file.display()
        ),
        Ok(metadata) if !metadata.is_file() => anyhow::bail!(
            "node credential path {} is not a regular file",
            file.display()
        ),
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", file.display())),
    }
}

fn persist_node_credential(file: &Path, credential: &StoredNodeCredential) -> Result<()> {
    use std::io::Write;

    let parent = file
        .parent()
        .with_context(|| format!("node credential path {} has no parent", file.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    if std::fs::symlink_metadata(parent)?.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to store node credential through symbolic-link directory {}",
            parent.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to secure {}", parent.display()))?;
    }

    let mut temporary = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "failed to create temporary credential in {}",
            parent.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(&serde_json::to_vec_pretty(credential)?)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(file).map_err(|error| {
        anyhow::anyhow!(
            "refusing to overwrite node credential {}: {}",
            file.display(),
            error.error
        )
    })?;
    Ok(())
}

pub(crate) fn local_node_credential_file(project: &Path, node: &str) -> PathBuf {
    let digest = Digest::sha256(node);
    let file_stem = digest.as_str().trim_start_matches("sha256:");
    project
        .join(".clusterflux-state")
        .join("nodes")
        .join(format!("{file_stem}.json"))
}

fn default_node_public_key_for_plan(node: &str) -> String {
    let private_key = generate_ed25519_private_key()
        .unwrap_or_else(|_| format!("unavailable-random-node-plan-key:{node}"));
    node_ed25519_public_key_from_private_key(&private_key)
        .unwrap_or_else(|_| format!("{node}-public-key"))
}

fn signed_node_request(
    node_private_key: &str,
    node: &str,
    request_kind: &str,
    request: CoordinatorRequest,
) -> Result<CoordinatorRequest> {
    let payload = serde_json::to_value(&request)?;
    let payload_digest = signed_request_payload_digest(&payload);
    let node_signature = sign_node_request(
        node_private_key,
        &NodeId::from(node),
        request_kind,
        &payload_digest,
        command_nonce(request_kind),
        unix_timestamp_seconds(),
    )
    .map_err(anyhow::Error::msg)?;
    Ok(CoordinatorRequest::SignedNode {
        node: node.to_owned(),
        node_signature,
        request: Box::new(request),
    })
}

pub(crate) fn default_node_id() -> String {
    std::env::var("CLUSTERFLUX_NODE_ID")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "node-local".to_owned())
}

fn parse_capability(cap: &str) -> Option<Capability> {
    match cap {
        "command" => Some(Capability::Command),
        "containers" => Some(Capability::Containers),
        "rootless-podman" => Some(Capability::RootlessPodman),
        "containerd-nerdctl" => Some(Capability::ContainerdNerdctl),
        "source-filesystem" => Some(Capability::SourceFilesystem),
        "source-git" => Some(Capability::SourceGit),
        "host-filesystem" => Some(Capability::HostFilesystem),
        "network" => Some(Capability::Network),
        "secrets" => Some(Capability::Secrets),
        "inbound-ports" => Some(Capability::InboundPorts),
        "arbitrary-syscalls" => Some(Capability::ArbitrarySyscalls),
        "vfs-artifacts" => Some(Capability::VfsArtifacts),
        "windows-command-dev" => Some(Capability::WindowsCommandDev),
        "artifact-transfer" => Some(Capability::ArtifactTransfer),
        _ => None,
    }
}
