use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clusterflux_client::MAX_CONTROL_FRAME_BYTES;
use clusterflux_core::{
    agent_ed25519_public_key_from_private_key, agent_workflow_request_scope_from_payload,
    sign_agent_workflow_request, signed_request_payload_digest, Digest, ProcessId, ProjectId,
    TaskDefinitionId, TaskDispatch, TaskInstanceId, TaskSpec, TenantId, WasmExportAbi,
};
use clusterflux_protocol::{
    AuthenticatedCoordinatorRequest, CoordinatorRequest, CoordinatorResponse,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::client::{stored_session_for_coordinator, JsonLineSession};
use crate::config::{
    default_hosted_coordinator_endpoint, read_cli_session, read_project_config, StoredCliSession,
};
use crate::errors::{cli_error_summary, cli_error_summary_for_category};
use crate::{BuildArgs, RunArgs};

mod local_services;
use local_services::{LocalCoordinator, LocalNodeWorker};

struct RunBundle {
    build_report: Value,
    digest: Digest,
    source_snapshot: Digest,
    module_base64: String,
    module_size_bytes: usize,
    entry_export: String,
    entry_stable_id: String,
    entry_name: String,
}

// The control request contains base64 (4/3 expansion), the authenticated
// envelope, TaskSpec metadata, and user/project identifiers. Reserve a fixed
// worst-case metadata budget so every module at or below this limit fits the
// bounded control frame without creating a process first.
const INLINE_BUNDLE_REQUEST_OVERHEAD_BYTES: usize = 96 * 1024;
pub(crate) const MAX_INLINE_WASM_MODULE_BYTES: usize =
    ((MAX_CONTROL_FRAME_BYTES - INLINE_BUNDLE_REQUEST_OVERHEAD_BYTES) / 4) * 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct RunPlan {
    pub(crate) project: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) requested_entrypoint: Option<String>,
    pub(crate) coordinator: CoordinatorSelection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hosted_coordinator_endpoint: Option<String>,
    pub(crate) session: CliSession,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct RunExecutionReport {
    pub(crate) plan: RunPlan,
    pub(crate) boundary: RunBoundaryEvidence,
    pub(crate) node_report: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct RunBoundaryEvidence {
    pub(crate) cli_process_started_node_process: bool,
    pub(crate) cli_process_started_coordinator_process: bool,
    pub(crate) coordinator_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) coordinator_process_id: Option<u32>,
    pub(crate) spawned_node_process_id: u32,
    pub(crate) node_session_requests: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum CoordinatorSelection {
    Hosted,
    LocalOverride(String),
    LocalOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum CliSession {
    Anonymous,
    HumanSession,
    AgentPublicKey {
        agent: String,
        public_key: String,
        public_key_fingerprint: Digest,
        #[serde(skip)]
        private_key: Option<String>,
        browser_interaction_required: bool,
    },
}

impl CliSession {
    pub(crate) fn is_authenticated(&self) -> bool {
        !matches!(self, Self::Anonymous)
    }
}

pub(crate) fn run_plan(args: RunArgs, cwd: PathBuf, session: CliSession) -> Result<RunPlan> {
    let (coordinator, hosted_coordinator_endpoint) = if let Some(url) = args.coordinator {
        (CoordinatorSelection::LocalOverride(url), None)
    } else if args.local {
        (CoordinatorSelection::LocalOnly, None)
    } else if session.is_authenticated() {
        (
            CoordinatorSelection::Hosted,
            Some(default_hosted_coordinator_endpoint()),
        )
    } else {
        (CoordinatorSelection::LocalOnly, None)
    };

    Ok(RunPlan {
        project: args.project.unwrap_or(cwd),
        requested_entrypoint: args.entry,
        coordinator,
        hosted_coordinator_endpoint,
        session,
    })
}

fn non_interactive_run_requires_auth_report(args: RunArgs, cwd: PathBuf) -> Value {
    let project = args.project.unwrap_or(cwd);
    let message = "non-interactive run requires an authenticated human or agent session unless --local or --coordinator is explicit";
    let next_actions = vec![
        "clusterflux login --browser",
        "set CLUSTERFLUX_AGENT_PRIVATE_KEY for automation",
        "pass --local to run against local services",
        "pass --coordinator for an explicit self-hosted coordinator",
    ];
    let mut machine_error = cli_error_summary_for_category("authentication", message);
    if let Some(object) = machine_error.as_object_mut() {
        object.insert("next_actions".to_owned(), json!(next_actions.clone()));
        object.insert("browser_opened".to_owned(), json!(false));
    }
    json!({
        "command": "run",
        "status": "authentication_required",
        "project_root": project,
        "requested_entrypoint": args.entry,
        "non_interactive": true,
        "browser_opened": false,
        "safe_failure": true,
        "message": message,
        "next_actions": next_actions,
        "external_website_required": false,
        "machine_error": machine_error,
    })
}

pub(crate) fn run_report(args: RunArgs, cwd: PathBuf, session: CliSession) -> Result<Value> {
    if args.non_interactive
        && !args.local
        && args.coordinator.is_none()
        && !session.is_authenticated()
    {
        return Ok(non_interactive_run_requires_auth_report(args, cwd));
    }
    let plan = run_plan(args, cwd, session)?;
    if should_execute_local_node(&plan) {
        return Ok(serde_json::to_value(execute_local_node_run(plan)?)?);
    }
    coordinator_run_report(plan)
}

fn coordinator_run_report(plan: RunPlan) -> Result<Value> {
    // Build, resolve the requested entrypoint, verify the module digest, and
    // enforce the accepted inline transport boundary before mutating the
    // coordinator. A failure here therefore cannot leave an active process.
    let bundle = build_bundle_for_run(&plan.project, plan.requested_entrypoint.as_deref())?;
    let selected_entrypoint = bundle.entry_name.clone();
    validate_inline_bundle_size(bundle.module_size_bytes)?;
    let config = read_project_config(&plan.project)?;
    let stored_session = read_cli_session(&plan.project)?;
    let coordinator = run_coordinator_endpoint(&plan, stored_session.as_ref())?;
    let bound_session = stored_session_for_coordinator(&coordinator, stored_session.as_ref());
    let tenant = bound_session
        .map(|session| session.tenant.clone())
        .or_else(|| config.as_ref().map(|config| config.tenant.clone()))
        .unwrap_or_else(|| "tenant".to_owned());
    let project = bound_session
        .map(|session| session.project.clone())
        .or_else(|| config.as_ref().map(|config| config.project.clone()))
        .unwrap_or_else(|| "project".to_owned());
    let user = bound_session
        .map(|session| session.user.clone())
        .or_else(|| config.as_ref().map(|config| config.user.clone()))
        .unwrap_or_else(|| "user".to_owned());
    let human_session_secret =
        human_run_session_secret(&plan, &coordinator, stored_session.as_ref())?;
    if matches!(plan.session, CliSession::HumanSession)
        && human_session_secret.is_none()
        && !crate::client::is_loopback_coordinator(&coordinator)
    {
        return Err(crate::errors::CliFailure::authentication_required(format!(
            "no authenticated CLI session matches coordinator {coordinator}"
        ))
        .with_coordinator(coordinator)
        .into());
    }
    let process = "vp-current".to_owned();
    let launch_attempt = new_launch_attempt_id();
    let mut session = JsonLineSession::connect(&coordinator)?;
    let request = authenticated_human_or_local_trusted_workflow(
        CoordinatorRequest::StartProcess {
            tenant: tenant.clone(),
            project: project.clone(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: process.clone(),
            launch_attempt: Some(launch_attempt.clone()),
            restart: false,
        },
        &plan.session,
        &user,
        human_session_secret.as_deref(),
    )?;
    let response = request_process_start_with_rollback(
        &mut session,
        request,
        &coordinator,
        &plan.session,
        &user,
        human_session_secret.as_deref(),
        &tenant,
        &project,
        &process,
        &launch_attempt,
    )?;
    let run_start = run_start_summary(&response);
    let status = run_start
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("coordinator_response");
    // The guest ABI validates the invocation against the registered entrypoint
    // name. Keep the stable id as bundle metadata, but dispatch the runtime
    // task under that registered name.
    let task_definition = selected_entrypoint.clone();
    let task_instance = format!("ti:{process}:main");
    let artifact_path = format!("/vfs/artifacts/{task_instance}-output.txt");
    let launch_task_response = if status == "started" {
        let vfs_epoch = match &response {
            CoordinatorResponse::ProcessStarted { epoch, .. } => *epoch,
            _ => 0,
        };
        let task_spec = TaskSpec {
            tenant: TenantId::new(tenant.clone()),
            project: ProjectId::new(project.clone()),
            process: ProcessId::new(process.clone()),
            task_definition: TaskDefinitionId::new(task_definition.clone()),
            task_instance: TaskInstanceId::new(task_instance.clone()),
            dispatch: TaskDispatch::CoordinatorNodeWasm {
                export: Some(bundle.entry_export.clone()),
                abi: WasmExportAbi::EntrypointV1,
            },
            environment_id: None,
            environment: None,
            environment_digest: None,
            required_capabilities: Default::default(),
            dependency_cache: None,
            source_snapshot: Some(bundle.source_snapshot.clone()),
            source_revision: None,
            required_artifacts: Vec::new(),
            requested_secrets: Vec::new(),
            args: Vec::new(),
            vfs_epoch,
            failure_policy: Default::default(),
            bundle_digest: Some(bundle.digest.clone()),
        };
        let launch_task_request = authenticated_human_or_local_trusted_workflow(
            CoordinatorRequest::LaunchTask {
                tenant: tenant.clone(),
                project: project.clone(),
                actor_user: None,
                actor_agent: None,
                agent_public_key_fingerprint: None,
                agent_signature: None,
                task_spec,
                wait_for_node: true,
                artifact_path: artifact_path.clone(),
                wasm_module_base64: bundle.module_base64,
            },
            &plan.session,
            &user,
            human_session_secret.as_deref(),
        )?;
        let launch = session
            .request_allow_error(launch_task_request)
            .and_then(|response| match response {
                response @ CoordinatorResponse::MainLaunched { .. } => Ok(response),
                response => anyhow::bail!(
                    "coordinator main launch was not acknowledged: {}",
                    serde_json::to_string(&response)?
                ),
            });
        match launch {
            Ok(launch) => Some(launch),
            Err(launch_error) => {
                let rollback = ProcessLaunchRollback {
                    cli_session: &plan.session,
                    fallback_user: &user,
                    human_session_secret: human_session_secret.as_deref(),
                    tenant: &tenant,
                    project: &project,
                    process: &process,
                    launch_attempt: &launch_attempt,
                };
                let cleanup = rollback_failed_process_launch_reconnecting(
                    &coordinator,
                    &rollback,
                    &json!({ "error": launch_error.to_string() }),
                );
                if let Err(cleanup_error) = cleanup {
                    anyhow::bail!("{launch_error}; process cleanup also failed: {cleanup_error}");
                }
                return Err(launch_error);
            }
        }
    } else {
        None
    };
    let main_launched = matches!(
        &launch_task_response,
        Some(CoordinatorResponse::MainLaunched { .. })
    );
    let workflow_actor = match &response {
        CoordinatorResponse::ProcessStarted { actor, .. } => Some(actor),
        _ => None,
    };
    Ok(json!({
        "command": "run",
        "status": if main_launched { "main_launched" } else { status },
        "project_root": plan.project,
        "entry": selected_entrypoint,
        "requested_entrypoint": plan.requested_entrypoint,
        "tenant": tenant,
        "project": project,
        "user": user,
        "workflow_actor": workflow_actor,
        "coordinator": coordinator,
        "process": process,
        "run_start": run_start,
        "task_definition": task_definition,
        "task_instance": task_instance,
        "bundle_build": bundle.build_report,
        "bundle_digest": bundle.digest,
        "bundle_module_size_bytes": bundle.module_size_bytes,
        "entry_export": bundle.entry_export,
        "entry_stable_id": bundle.entry_stable_id,
        "entry_abi_version": 1,
        "worker_placement_requested": launch_task_response.is_some(),
        "task_launch": launch_task_response,
        "coordinator_response": response,
        "coordinator_session_requests": session.requests(),
        "external_website_required": false,
    }))
}

#[allow(clippy::too_many_arguments)]
fn request_process_start_with_rollback(
    session: &mut JsonLineSession,
    request: CoordinatorRequest,
    coordinator: &str,
    cli_session: &CliSession,
    fallback_user: &str,
    human_session_secret: Option<&str>,
    tenant: &str,
    project: &str,
    process: &str,
    launch_attempt: &str,
) -> Result<CoordinatorResponse> {
    let rollback = ProcessLaunchRollback {
        cli_session,
        fallback_user,
        human_session_secret,
        tenant,
        project,
        process,
        launch_attempt,
    };
    match session.request_allow_error(request) {
        Ok(response) => {
            if let CoordinatorResponse::ProcessStarted {
                launch_attempt: acknowledged_attempt,
                ..
            } = &response
            {
                if acknowledged_attempt.as_deref() != Some(launch_attempt) {
                    let ownership_error = anyhow::anyhow!(
                        "coordinator returned a process-start acknowledgement owned by a different launch attempt"
                    );
                    rollback_failed_process_launch_reconnecting(
                        coordinator,
                        &rollback,
                        &json!({ "error": ownership_error.to_string(), "phase": "start_process_ownership" }),
                    )?;
                    return Err(ownership_error);
                }
            }
            Ok(response)
        }
        Err(start_error) => {
            let cleanup = rollback_failed_process_launch_reconnecting(
                coordinator,
                &rollback,
                &json!({ "error": start_error.to_string(), "phase": "start_process" }),
            );
            if let Err(cleanup_error) = cleanup {
                let cleanup_message = cleanup_error.to_string();
                if !cleanup_message.contains("process abort requires an active virtual process") {
                    anyhow::bail!(
                        "{start_error}; ambiguous process-start cleanup also failed: {cleanup_error}"
                    );
                }
            }
            Err(start_error)
        }
    }
}

static NEXT_LAUNCH_ATTEMPT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
const LOCAL_MAIN_PLACEMENT_TIMEOUT: Duration = Duration::from_secs(5 * 60);

fn new_launch_attempt_id() -> String {
    let sequence = NEXT_LAUNCH_ATTEMPT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("launch-{}-{nanos}-{sequence}", std::process::id())
}

struct ProcessLaunchRollback<'a> {
    cli_session: &'a CliSession,
    fallback_user: &'a str,
    human_session_secret: Option<&'a str>,
    tenant: &'a str,
    project: &'a str,
    process: &'a str,
    launch_attempt: &'a str,
}

fn validate_inline_bundle_size(module_size_bytes: usize) -> Result<()> {
    if module_size_bytes <= MAX_INLINE_WASM_MODULE_BYTES {
        return Ok(());
    }
    anyhow::bail!(
        "built Wasm module is {module_size_bytes} bytes, but the current {}-byte inline control frame supports at most about {} KiB ({} raw bytes); reduce the bundle dependency or optimization footprint. Larger bundles require an out-of-band transport. No virtual process was created",
        MAX_CONTROL_FRAME_BYTES,
        MAX_INLINE_WASM_MODULE_BYTES / 1024,
        MAX_INLINE_WASM_MODULE_BYTES,
    )
}

fn rollback_failed_process_launch(
    session: &mut JsonLineSession,
    context: &ProcessLaunchRollback<'_>,
    launch_response: &Value,
) -> Result<()> {
    let rollback = authenticated_human_or_local_trusted_workflow(
        CoordinatorRequest::AbortProcess {
            tenant: context.tenant.to_owned(),
            project: context.project.to_owned(),
            actor_user: context.fallback_user.to_owned(),
            process: context.process.to_owned(),
            launch_attempt: Some(context.launch_attempt.to_owned()),
        },
        context.cli_session,
        context.fallback_user,
        context.human_session_secret,
    )?;
    let rollback_response = session.request_allow_error(rollback)?;
    if !matches!(
        rollback_response,
        CoordinatorResponse::ProcessAborted { .. }
    ) {
        anyhow::bail!(
            "coordinator main launch failed ({launch_response}) and rollback was not acknowledged ({}); inspect virtual process {} before retrying",
            serde_json::to_string(&rollback_response)?,
            context.process
        );
    }
    Ok(())
}

fn rollback_failed_process_launch_reconnecting(
    coordinator: &str,
    context: &ProcessLaunchRollback<'_>,
    launch_response: &Value,
) -> Result<()> {
    let mut cleanup_session = JsonLineSession::connect(coordinator)
        .context("open a fresh coordinator connection for failed-launch cleanup")?;
    rollback_failed_process_launch(&mut cleanup_session, context, launch_response)
}

fn build_bundle_for_run(project: &Path, requested_entrypoint: Option<&str>) -> Result<RunBundle> {
    let build_report = crate::build::build_report(
        BuildArgs {
            project: Some(project.to_path_buf()),
            entry: requested_entrypoint.map(str::to_owned),
            source_provider: None,
            disabled_source_providers: Vec::new(),
            output: None,
            json: true,
        },
        project.to_path_buf(),
    )?;
    if build_report.get("status").and_then(Value::as_str) != Some("built") {
        let diagnostics = build_report
            .get("diagnostics")
            .cloned()
            .unwrap_or(Value::Null);
        anyhow::bail!("Clusterflux bundle build was blocked before run: {diagnostics}");
    }
    let artifact = build_report
        .get("bundle_artifact")
        .context("bundle build response omitted bundle_artifact")?;
    let module_path = artifact
        .get("module")
        .and_then(Value::as_str)
        .context("bundle build response omitted module path")?;
    let digest: Digest = serde_json::from_value(
        artifact
            .get("execution_module_digest")
            .cloned()
            .context("bundle build response omitted execution module digest")?,
    )?;
    let module = std::fs::read(module_path)
        .with_context(|| format!("failed to read built Wasm module {module_path}"))?;
    let actual_digest = Digest::sha256(&module);
    if actual_digest != digest {
        anyhow::bail!(
            "built Wasm module digest changed before run: expected {digest}, actual {actual_digest}"
        );
    }
    let descriptor = build_report
        .get("selected_entrypoint")
        .context("bundle build report omitted selected entrypoint")?;
    let entry_name = descriptor
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| requested_entrypoint.is_none_or(|requested| requested == *name))
        .context("bundle build report selected an unexpected entrypoint")?
        .to_owned();
    if descriptor.get("abi_version").and_then(Value::as_u64) != Some(1) {
        anyhow::bail!("entrypoint `{entry_name}` does not use supported Clusterflux ABI version 1");
    }
    let entry_export = descriptor
        .get("export")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("entrypoint `{entry_name}` descriptor omitted its Wasm export"))?
        .to_owned();
    let entry_stable_id = descriptor
        .get("stable_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("entrypoint `{entry_name}` descriptor omitted its stable id"))?
        .to_owned();
    let source_snapshot: Digest = serde_json::from_value(
        build_report
            .pointer("/source_snapshot/digest")
            .cloned()
            .context("bundle build response omitted source snapshot digest")?,
    )?;
    Ok(RunBundle {
        build_report,
        digest,
        source_snapshot,
        module_size_bytes: module.len(),
        module_base64: BASE64_STANDARD.encode(module),
        entry_export,
        entry_stable_id,
        entry_name,
    })
}

fn human_run_session_secret(
    plan: &RunPlan,
    coordinator: &str,
    stored_session: Option<&StoredCliSession>,
) -> Result<Option<String>> {
    if !matches!(plan.session, CliSession::HumanSession) {
        return Ok(None);
    }
    if let Ok(token) = std::env::var("CLUSTERFLUX_TOKEN") {
        if !token.trim().is_empty() {
            return Ok(Some(token));
        }
    }
    Ok(stored_session_for_coordinator(coordinator, stored_session)
        .and_then(|session| session.session_secret.clone()))
}

fn authenticated_human_or_local_trusted_workflow(
    mut request: CoordinatorRequest,
    session: &CliSession,
    fallback_user: &str,
    human_session_secret: Option<&str>,
) -> Result<CoordinatorRequest> {
    if matches!(session, CliSession::HumanSession) {
        if let Some(session_secret) = human_session_secret {
            let request = AuthenticatedCoordinatorRequest::try_from(request).map_err(|error| {
                anyhow::anyhow!(
                    "run request is not available through an authenticated session: {error}"
                )
            })?;
            return Ok(CoordinatorRequest::Authenticated {
                session_secret: session_secret.to_owned(),
                request,
            });
        }
    }
    add_workflow_actor_fields(&mut request, session, fallback_user)?;
    Ok(request)
}

fn run_coordinator_endpoint(
    plan: &RunPlan,
    stored_session: Option<&StoredCliSession>,
) -> Result<String> {
    match &plan.coordinator {
        CoordinatorSelection::Hosted => Ok(stored_session
            .filter(|session| {
                matches!(plan.session, CliSession::HumanSession) && session.session_secret.is_some()
            })
            .map(|session| session.coordinator.clone())
            .or_else(|| plan.hosted_coordinator_endpoint.clone())
            .unwrap_or_else(default_hosted_coordinator_endpoint)),
        CoordinatorSelection::LocalOverride(coordinator) => Ok(coordinator.clone()),
        CoordinatorSelection::LocalOnly => {
            anyhow::bail!("local-only run should execute through local services")
        }
    }
}

pub(crate) fn run_start_summary(response: &CoordinatorResponse) -> Value {
    if let CoordinatorResponse::ProcessStarted {
        process,
        epoch,
        actor,
        ..
    } = response
    {
        return json!({
            "status": "started",
            "accepted": true,
            "process": process,
            "coordinator_epoch": epoch,
            "actor": actor,
            "restart": false,
            "single_active_process_boundary": true,
            "next_actions": [
                "clusterflux process status",
                "clusterflux logs",
                "clusterflux process cancel"
            ],
        });
    }

    let (message, machine_error) = match response {
        CoordinatorResponse::Error { error } => (
            error.message.as_str(),
            crate::errors::cli_error_summary_for_api_error(error),
        ),
        _ => (
            "coordinator returned an unexpected response to process start",
            cli_error_summary("coordinator returned an unexpected response to process start"),
        ),
    };
    let active_conflict = machine_error
        .get("code")
        .and_then(Value::as_str)
        .is_some_and(|code| code == "active_process_exists")
        || message.contains("already has active virtual process");
    let error_category = machine_error
        .get("category")
        .cloned()
        .unwrap_or_else(|| json!("unknown"));
    let stable_exit_code = machine_error
        .get("stable_exit_code")
        .cloned()
        .unwrap_or_else(|| json!(1));
    json!({
        "status": if active_conflict { "blocked_active_process" } else { "coordinator_rejected" },
        "accepted": false,
        "category": if active_conflict { "active_process_already_running" } else { "coordinator" },
        "error_category": error_category,
        "stable_exit_code": stable_exit_code,
        "machine_error": machine_error,
        "message": message,
        "restart": false,
        "single_active_process_boundary": true,
        "safe_failure": true,
        "next_actions": if active_conflict {
            json!([
                "clusterflux process list",
                "clusterflux process status",
                "clusterflux debug attach",
                "clusterflux process restart --yes",
                "clusterflux process cancel --yes",
                "clusterflux process abort --yes",
                "use another Coordinator Project"
            ])
        } else {
            json!(["clusterflux doctor", "check coordinator status"])
        },
    })
}

pub(crate) fn should_execute_local_node(plan: &RunPlan) -> bool {
    match &plan.coordinator {
        CoordinatorSelection::LocalOnly => true,
        CoordinatorSelection::LocalOverride(coordinator) => !coordinator.contains("://"),
        CoordinatorSelection::Hosted => false,
    }
}

fn execute_local_node_run(plan: RunPlan) -> Result<RunExecutionReport> {
    let environments = clusterflux_core::discover_environments(&plan.project)?;
    let detected = clusterflux_core::NodeCapabilities::detect_current();
    if environments.iter().any(|environment| {
        environment
            .requirements
            .capabilities
            .contains(&clusterflux_core::Capability::RootlessPodman)
    }) && !detected
        .capabilities
        .contains(&clusterflux_core::Capability::RootlessPodman)
    {
        anyhow::bail!(
            "local project declares a Linux container environment, but rootless Podman is not available; configure rootless Podman or attach a capable user node"
        );
    }
    let local_coordinator = match &plan.coordinator {
        CoordinatorSelection::LocalOverride(coordinator) => LocalCoordinator::external(coordinator),
        CoordinatorSelection::LocalOnly => LocalCoordinator::start_ephemeral()?,
        CoordinatorSelection::Hosted => anyhow::bail!("local node execution requires local mode"),
    };
    let coordinator_address = local_coordinator.address.clone();
    let mut coordinator_plan = plan.clone();
    coordinator_plan.coordinator =
        CoordinatorSelection::LocalOverride(format!("clusterflux+tcp://{coordinator_address}"));
    let run = coordinator_run_report(coordinator_plan)?;
    let launch_type = run.pointer("/task_launch/type").and_then(Value::as_str);
    if launch_type != Some("main_launched") {
        anyhow::bail!("local coordinator refused the Wasm entrypoint launch: {run}");
    }
    let process = run
        .get("process")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("coordinator run report omitted virtual process id"))?;
    let task = run
        .pointer("/task_launch/task_instance")
        .or_else(|| run.get("task_instance"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("coordinator run report omitted entrypoint task id"))?;
    let pre_node_process_status = wait_for_local_main_placement(&coordinator_address, process)?;
    let enrollment_grant = create_local_node_enrollment_grant(&coordinator_address)?;
    let mut worker =
        LocalNodeWorker::start(&coordinator_address, &plan.project, &enrollment_grant)?;
    let spawned_node_process_id = worker.process_id;
    let join = wait_for_local_main_completion(&coordinator_address, process, task)?;
    worker.stop();
    let node_report = json!({
        "node_status": "completed",
        "execution_substrate": "wasm",
        "task_spawn_host_import": true,
        "pre_node_process_status": pre_node_process_status,
        "run": run,
        "join": join,
    });

    Ok(RunExecutionReport {
        plan,
        boundary: RunBoundaryEvidence {
            cli_process_started_node_process: true,
            cli_process_started_coordinator_process: local_coordinator.process_id.is_some(),
            coordinator_address,
            coordinator_process_id: local_coordinator.process_id,
            spawned_node_process_id,
            node_session_requests: 0,
        },
        node_report,
    })
}

fn local_process_status(coordinator: &str) -> Result<CoordinatorResponse> {
    let mut session = JsonLineSession::connect(coordinator)?;
    session.request_allow_error(CoordinatorRequest::ListProcesses {
        tenant: "tenant".to_owned(),
        project: "project".to_owned(),
        actor_user: "user".to_owned(),
    })
}

fn create_local_node_enrollment_grant(coordinator: &str) -> Result<String> {
    let mut session = JsonLineSession::connect(coordinator)?;
    let response = session.request_allow_error(CoordinatorRequest::CreateNodeEnrollmentGrant {
        tenant: "tenant".to_owned(),
        project: "project".to_owned(),
        actor_user: "user".to_owned(),
        ttl_seconds: 60,
    })?;
    match response {
        CoordinatorResponse::NodeEnrollmentGrantCreated { grant, .. } => Ok(grant),
        response => anyhow::bail!(
            "local coordinator refused node enrollment: {}",
            serde_json::to_string(&response)?
        ),
    }
}

fn wait_for_local_main_placement(coordinator: &str, process: &str) -> Result<Value> {
    let started = Instant::now();
    let mut idle_backoff = Duration::from_millis(100);
    loop {
        let status = local_process_status(coordinator)?;
        let process_status = match &status {
            CoordinatorResponse::ProcessStatuses { processes, .. } => processes
                .iter()
                .find(|candidate| candidate.process.as_str() == process),
            response => anyhow::bail!(
                "local coordinator returned an unexpected process-status response: {}",
                serde_json::to_string(response)?
            ),
        };
        match process_status.and_then(|status| status.main_wait_state.as_deref()) {
            Some("waiting_for_node") => return serde_json::to_value(status).map_err(Into::into),
            _ if started.elapsed() > LOCAL_MAIN_PLACEMENT_TIMEOUT => anyhow::bail!(
                "local coordinator main `{process}` did not become observably parked on node placement before the local node launch: {}",
                serde_json::to_string(&status)?
            ),
            _ => {
                thread::sleep(idle_backoff);
                idle_backoff = (idle_backoff * 2).min(Duration::from_secs(2));
            }
        }
    }
}

fn wait_for_local_main_completion(coordinator: &str, process: &str, task: &str) -> Result<Value> {
    let started = Instant::now();
    let mut idle_backoff = Duration::from_millis(100);
    loop {
        let mut session = JsonLineSession::connect(coordinator)?;
        let response = session.request_allow_error(CoordinatorRequest::JoinTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: process.to_owned(),
            task: task.to_owned(),
        })?;
        let join = match &response {
            CoordinatorResponse::TaskJoined { join } => join,
            response => anyhow::bail!(
                "local coordinator returned an unexpected task-join response: {}",
                serde_json::to_string(response)?
            ),
        };
        match &join.state {
            clusterflux_core::TaskJoinState::Completed => {
                return serde_json::to_value(response).map_err(Into::into)
            }
            clusterflux_core::TaskJoinState::Failed
            | clusterflux_core::TaskJoinState::Cancelled => {
                let events = session.request_allow_error(CoordinatorRequest::ListTaskEvents {
                    tenant: "tenant".to_owned(),
                    project: "project".to_owned(),
                    actor_user: "user".to_owned(),
                    process: Some(process.to_owned()),
                })?;
                anyhow::bail!(
                    "local Wasm entrypoint failed: {}; task events: {}",
                    serde_json::to_string(&response)?,
                    serde_json::to_string(&events)?
                )
            }
            _ if started.elapsed() > clusterflux_core::limits::task_join_timeout() => {
                return Err(anyhow::Error::new(
                    clusterflux_core::limits::TaskJoinError::timeout(
                        clusterflux_core::TaskInstanceId::from(task),
                        clusterflux_core::limits::task_join_timeout(),
                    ),
                ));
            }
            clusterflux_core::TaskJoinState::Pending => {
                thread::sleep(idle_backoff);
                idle_backoff = (idle_backoff * 2).min(Duration::from_secs(2));
            }
        }
    }
}

pub(crate) fn session_from_env() -> Result<CliSession> {
    if let Some(session) = agent_session_from_keys(
        std::env::var("CLUSTERFLUX_AGENT_ID").unwrap_or_else(|_| "agent".to_owned()),
        std::env::var("CLUSTERFLUX_AGENT_PUBLIC_KEY").ok(),
        std::env::var("CLUSTERFLUX_AGENT_PRIVATE_KEY").ok(),
    )? {
        return Ok(session);
    }
    if std::env::var_os("CLUSTERFLUX_TOKEN").is_some() {
        return Ok(CliSession::HumanSession);
    }
    Ok(CliSession::Anonymous)
}

pub(crate) fn agent_session_from_keys(
    agent: String,
    configured_public_key: Option<String>,
    private_key: Option<String>,
) -> Result<Option<CliSession>> {
    if let Some(private_key) = private_key {
        let derived_public_key = agent_ed25519_public_key_from_private_key(&private_key)
            .map_err(anyhow::Error::msg)
            .context("CLUSTERFLUX_AGENT_PRIVATE_KEY is not a valid Ed25519 private key")?;
        if let Some(configured_public_key) = configured_public_key.as_deref() {
            if configured_public_key != derived_public_key {
                anyhow::bail!(
                    "CLUSTERFLUX_AGENT_PUBLIC_KEY does not match CLUSTERFLUX_AGENT_PRIVATE_KEY"
                );
            }
        }
        return Ok(Some(CliSession::AgentPublicKey {
            agent,
            public_key_fingerprint: Digest::sha256(derived_public_key.as_bytes()),
            public_key: derived_public_key,
            private_key: Some(private_key),
            browser_interaction_required: false,
        }));
    }
    if configured_public_key.is_some() {
        anyhow::bail!(
            "CLUSTERFLUX_AGENT_PUBLIC_KEY identifies a registered key but cannot authenticate; set CLUSTERFLUX_AGENT_PRIVATE_KEY to prove key possession"
        );
    }
    Ok(None)
}

pub(crate) fn session_from_sources(project: &Path) -> Result<CliSession> {
    let session = session_from_env()?;
    if session.is_authenticated() {
        return Ok(session);
    }
    if read_cli_session(project)?.is_some() {
        return Ok(CliSession::HumanSession);
    }
    Ok(CliSession::Anonymous)
}

fn add_workflow_actor_fields(
    request: &mut CoordinatorRequest,
    session: &CliSession,
    fallback_user: &str,
) -> Result<()> {
    match session {
        CliSession::AgentPublicKey {
            agent,
            public_key: _,
            public_key_fingerprint,
            private_key,
            ..
        } => {
            match request {
                CoordinatorRequest::StartProcess {
                    actor_agent,
                    agent_public_key_fingerprint,
                    ..
                }
                | CoordinatorRequest::LaunchTask {
                    actor_agent,
                    agent_public_key_fingerprint,
                    ..
                } => {
                    *actor_agent = Some(agent.clone());
                    *agent_public_key_fingerprint = Some(public_key_fingerprint.clone());
                }
                _ => anyhow::bail!(
                    "{} is not available to an agent workflow session",
                    request.operation()
                ),
            }
            if let Some(signature) =
                agent_signature_for_request(request, agent, private_key.as_deref())
            {
                match request {
                    CoordinatorRequest::StartProcess {
                        agent_signature, ..
                    }
                    | CoordinatorRequest::LaunchTask {
                        agent_signature, ..
                    } => *agent_signature = Some(signature),
                    _ => unreachable!("agent workflow request was checked above"),
                }
            }
        }
        CliSession::HumanSession | CliSession::Anonymous => match request {
            CoordinatorRequest::StartProcess { actor_user, .. }
            | CoordinatorRequest::LaunchTask { actor_user, .. } => {
                *actor_user = Some(fallback_user.to_owned());
            }
            CoordinatorRequest::AbortProcess { actor_user, .. } => {
                *actor_user = fallback_user.to_owned();
            }
            _ => {}
        },
    }
    Ok(())
}

fn agent_signature_for_request(
    request: &CoordinatorRequest,
    agent: &str,
    private_key: Option<&str>,
) -> Option<clusterflux_core::AgentSignedRequest> {
    let private_key = private_key?;
    let payload = serde_json::to_value(request).ok()?;
    let scope = agent_workflow_request_scope_from_payload(&payload).ok()?;
    let agent = clusterflux_core::AgentId::from(agent);
    let payload_digest = signed_request_payload_digest(&payload);
    sign_agent_workflow_request(
        private_key,
        scope.for_agent(&agent),
        &payload_digest,
        crate::tools::command_nonce("agent-signature"),
        crate::tools::unix_timestamp_seconds(),
    )
    .ok()
}

#[cfg(test)]
mod transactional_launch_tests {
    use std::io::{BufRead as _, ErrorKind, Write as _};
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn inline_module_limit_is_derived_from_the_control_frame() {
        assert_eq!(MAX_CONTROL_FRAME_BYTES, 16 * 1024 * 1024);
        assert_eq!(MAX_INLINE_WASM_MODULE_BYTES % 3, 0);
        let inline_limit = std::hint::black_box(MAX_INLINE_WASM_MODULE_BYTES);
        assert!((11 * 1024 * 1024..=12 * 1024 * 1024).contains(&inline_limit));
        validate_inline_bundle_size(MAX_INLINE_WASM_MODULE_BYTES).unwrap();
        let error = validate_inline_bundle_size(MAX_INLINE_WASM_MODULE_BYTES + 1)
            .unwrap_err()
            .to_string();
        assert!(error.contains("No virtual process was created"));
        assert!(error.contains("out-of-band transport"));
    }

    #[test]
    fn build_failure_occurs_before_any_coordinator_connection() {
        let project = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let plan = RunPlan {
            project: project.path().to_path_buf(),
            requested_entrypoint: Some("build".to_owned()),
            coordinator: CoordinatorSelection::LocalOverride(
                listener.local_addr().unwrap().to_string(),
            ),
            hosted_coordinator_endpoint: None,
            session: CliSession::Anonymous,
        };

        let error = coordinator_run_report(plan).unwrap_err().to_string();
        assert!(
            error.contains("Cargo.toml") || error.contains("project"),
            "unexpected build error: {error}"
        );
        assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn failed_main_launch_uses_explicit_abort_rollback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let wire: Value = serde_json::from_str(&line).unwrap();
            let payload = wire.get("payload").unwrap();
            assert_eq!(
                payload.get("type").and_then(Value::as_str),
                Some("abort_process")
            );
            assert_eq!(
                payload.get("tenant").and_then(Value::as_str),
                Some("tenant-a")
            );
            assert_eq!(
                payload.get("project").and_then(Value::as_str),
                Some("project-a")
            );
            assert_eq!(
                payload.get("process").and_then(Value::as_str),
                Some("vp-current")
            );
            assert_eq!(
                payload.get("launch_attempt").and_then(Value::as_str),
                Some("launch-test")
            );
            writeln!(
                stream,
                "{}",
                json!({
                    "type": "process_aborted",
                    "process": "vp-current",
                    "aborted_tasks": [],
                    "affected_nodes": []
                })
            )
            .unwrap();
        });
        let mut session = JsonLineSession::connect(&address.to_string()).unwrap();
        let rollback = ProcessLaunchRollback {
            cli_session: &CliSession::Anonymous,
            fallback_user: "user-a",
            human_session_secret: None,
            tenant: "tenant-a",
            project: "project-a",
            process: "vp-current",
            launch_attempt: "launch-test",
        };
        rollback_failed_process_launch(
            &mut session,
            &rollback,
            &json!({"type": "error", "message": "main launch failed"}),
        )
        .unwrap();
        server.join().unwrap();
    }

    #[test]
    fn dropped_start_response_reconnects_and_aborts_ambiguous_process() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut start_line = String::new();
            std::io::BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut start_line)
                .unwrap();
            assert!(start_line.contains("\"type\":\"start_process\""));
            assert!(start_line.contains("\"launch_attempt\":\"launch-test\""));
            drop(stream);

            let (mut cleanup_stream, _) = listener.accept().unwrap();
            let mut cleanup_line = String::new();
            std::io::BufReader::new(cleanup_stream.try_clone().unwrap())
                .read_line(&mut cleanup_line)
                .unwrap();
            assert!(cleanup_line.contains("\"type\":\"abort_process\""));
            assert!(cleanup_line.contains("\"launch_attempt\":\"launch-test\""));
            writeln!(
                cleanup_stream,
                "{}",
                json!({
                    "type": "process_aborted",
                    "process": "vp-current",
                    "aborted_tasks": [],
                    "affected_nodes": []
                })
            )
            .unwrap();
            listener.set_nonblocking(true).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(25));
            assert!(matches!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            ));
        });
        let mut session = JsonLineSession::connect(&address).unwrap();
        let error = request_process_start_with_rollback(
            &mut session,
            CoordinatorRequest::StartProcess {
                tenant: "tenant-a".to_owned(),
                project: "project-a".to_owned(),
                actor_user: Some("user-a".to_owned()),
                actor_agent: None,
                agent_public_key_fingerprint: None,
                agent_signature: None,
                process: "vp-current".to_owned(),
                launch_attempt: Some("launch-test".to_owned()),
                restart: false,
            },
            &address,
            &CliSession::Anonymous,
            "user-a",
            None,
            "tenant-a",
            "project-a",
            "vp-current",
            "launch-test",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("closed") || error.contains("response"));
        server.join().unwrap();
    }

    #[test]
    fn definitive_start_rejection_does_not_abort_existing_process() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let wire: Value = serde_json::from_str(&line).unwrap();
            let request_id = wire["request_id"].as_str().unwrap();
            writeln!(
                stream,
                "{}",
                serde_json::to_value(clusterflux_protocol::CoordinatorResponse::error(
                    request_id,
                    "project already has active virtual process vp-existing"
                ))
                .unwrap()
            )
            .unwrap();
            listener.set_nonblocking(true).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(25));
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        });
        let mut session = JsonLineSession::connect(&address).unwrap();
        let response = request_process_start_with_rollback(
            &mut session,
            CoordinatorRequest::StartProcess {
                tenant: "tenant-a".to_owned(),
                project: "project-a".to_owned(),
                actor_user: Some("user-a".to_owned()),
                actor_agent: None,
                agent_public_key_fingerprint: None,
                agent_signature: None,
                process: "vp-current".to_owned(),
                launch_attempt: Some("launch-rejected".to_owned()),
                restart: false,
            },
            &address,
            &CliSession::Anonymous,
            "user-a",
            None,
            "tenant-a",
            "project-a",
            "vp-current",
            "launch-rejected",
        )
        .unwrap();
        assert!(matches!(response, CoordinatorResponse::Error { .. }));
        server.join().unwrap();
    }
}
