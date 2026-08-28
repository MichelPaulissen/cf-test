use std::path::PathBuf;

use anyhow::Result;
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};
use serde_json::{json, Value};

use crate::client::{
    authenticated_or_local_trusted_request, list_attached_nodes_if_available_with_session,
    list_task_events_if_available_with_session, stored_session_for_coordinator, JsonLineSession,
};
use crate::config::{
    effective_project_scope, effective_scope_value, project_config_file, read_cli_session,
    read_project_config, write_cli_session, write_project_config, ProjectConfig, StoredCliSession,
};
use crate::process::process_list_report_with_session;
use crate::process_events::project_quota_posture;
use crate::{
    bundle_inspection, discovered_environment_names, BundleInspectArgs, ProcessListArgs,
    ProjectInitArgs, ProjectListArgs, ProjectSelectArgs, ProjectStatusArgs,
};

pub(crate) fn project_init_report(args: ProjectInitArgs, cwd: PathBuf) -> Result<Value> {
    let stored_session = read_cli_session(&cwd)?;
    let tenant = session_or_effective_scope_value(
        stored_session.as_ref(),
        &args.scope.tenant,
        |session| session.tenant.as_str(),
        "tenant",
    );
    let project = args.new_project.clone();
    let user = session_or_effective_scope_value(
        stored_session.as_ref(),
        &args.scope.user,
        |session| session.user.as_str(),
        "user",
    );
    let coordinator = args.scope.coordinator.clone().or_else(|| {
        stored_session
            .as_ref()
            .map(|session| session.coordinator.clone())
    });
    let name = args.name.clone();
    let config = ProjectConfig {
        tenant: tenant.clone(),
        project: project.clone(),
        user: user.clone(),
        coordinator: coordinator.clone(),
    };
    let config_file = project_config_file(&cwd);
    if config_file.exists() && !args.yes {
        anyhow::bail!(
            "{} already exists; rerun with --yes to update the project link",
            config_file.display()
        );
    }
    let mut coordinator_session_requests = 0;
    let coordinator_response = if let Some(coordinator) = &coordinator {
        let mut session = JsonLineSession::connect(coordinator)?;
        let request = authenticated_or_local_trusted_request(
            coordinator,
            stored_session.as_ref(),
            CoordinatorRequest::CreateProject {
                tenant: tenant.clone(),
                actor_user: user.clone(),
                project: project.clone(),
                name: name.clone(),
            },
        )?;
        let response = session.request(request)?;
        coordinator_session_requests = session.requests();
        Some(response)
    } else {
        None
    };
    write_project_config(&cwd, &config)?;
    let created_or_linked_project = match coordinator_response.as_ref() {
        Some(CoordinatorResponse::ProjectCreated { project, .. }) => serde_json::to_value(project)?,
        Some(_) => anyhow::bail!("coordinator returned an unexpected project-create response"),
        None => json!({
            "id": config.project.clone(),
            "tenant": config.tenant.clone(),
            "name": args.name.clone(),
        }),
    };
    Ok(json!({
        "command": "project init",
        "source": if coordinator.is_some() { "public_coordinator_api" } else { "local_project_config" },
        "external_website_required": false,
        "project_config_written": true,
        "project_config_write_after_coordinator_acceptance": coordinator.is_some(),
        "coordinator_create_before_local_write": coordinator.is_some(),
        "coordinator_session_requests": coordinator_session_requests,
        "created_or_linked_project": created_or_linked_project,
        "current_directory_link": {
            "cwd": cwd,
            "config_file": config_file,
            "config_format": "clusterflux_project_config_v1",
            "links_current_directory": true,
            "writes_current_directory_only": true,
            "external_website_required": false,
        },
        "safe_defaults": {
            "tenant": config.tenant.clone(),
            "project": config.project.clone(),
            "user": config.user.clone(),
            "coordinator": config.coordinator.clone(),
            "project_name": args.name.clone(),
            "default_project_id_used": args.new_project == "project",
            "default_project_name_used": args.name == "Clusterflux Project",
            "browser_interaction_required": false,
            "external_website_required": false,
        },
        "project_config": config,
        "config_file": project_config_file(&cwd),
        "coordinator_response": coordinator_response,
    }))
}

pub(crate) fn project_status_report(args: ProjectStatusArgs, cwd: PathBuf) -> Result<Value> {
    let config = read_project_config(&cwd)?;
    let stored_session = read_cli_session(&cwd)?;
    let mut effective_scope = effective_project_scope(&args.scope, config.as_ref());
    if effective_scope.coordinator.is_none() {
        effective_scope.coordinator = stored_session
            .as_ref()
            .filter(|session| session.session_secret.is_some())
            .map(|session| session.coordinator.clone());
    }
    if let (Some(config), Some(session)) = (config.as_ref(), stored_session.as_ref()) {
        let same_coordinator = effective_scope
            .coordinator
            .as_deref()
            .is_some_and(|coordinator| {
                crate::client::control_endpoint_identity(coordinator).ok()
                    == crate::client::control_endpoint_identity(&session.coordinator).ok()
            });
        if same_coordinator
            && (session.tenant != config.tenant
                || session.project != config.project
                || session.user != config.user)
        {
            anyhow::bail!(
                "stored CLI session is for {}/{}/{} but this workspace is configured for {}/{}/{}; run `clusterflux login --browser` from this workspace",
                session.tenant,
                session.project,
                session.user,
                config.tenant,
                config.project,
                config.user,
            );
        }
    }
    if let Some(bound_session) = effective_scope
        .coordinator
        .as_deref()
        .and_then(|coordinator| {
            stored_session_for_coordinator(coordinator, stored_session.as_ref())
        })
    {
        effective_scope.tenant = bound_session.tenant.clone();
        effective_scope.project = bound_session.project.clone();
        effective_scope.user = bound_session.user.clone();
    }
    let inspection = bundle_inspection(
        BundleInspectArgs {
            project: Some(cwd.clone()),
            source_provider: None,
            disabled_source_providers: Vec::new(),
            json: true,
        },
        cwd.clone(),
    )
    .ok();
    let coordinator = effective_scope.coordinator.clone();
    let attached_nodes = list_attached_nodes_if_available_with_session(
        coordinator.as_deref(),
        &effective_scope,
        stored_session.as_ref(),
    )?;
    let coordinator_response = list_task_events_if_available_with_session(
        coordinator.as_deref(),
        &effective_scope,
        None,
        stored_session.as_ref(),
    )?;
    let process_report = process_list_report_with_session(
        ProcessListArgs {
            scope: effective_scope.clone(),
        },
        stored_session.as_ref(),
    )?;
    let discovered_environments = discovered_environment_names(inspection.as_ref());
    let active_process = process_report
        .get("processes")
        .and_then(Value::as_array)
        .and_then(|processes| processes.first())
        .and_then(|process| process.get("process"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            if process_report.get("status").and_then(Value::as_str) == Some("ok") {
                "none".to_owned()
            } else {
                "unknown_without_coordinator".to_owned()
            }
        });
    let quota_posture = project_quota_posture(&attached_nodes, coordinator_response.as_ref());
    Ok(json!({
        "command": "project status",
        "cwd": cwd,
        "tenant": effective_scope.tenant,
        "project": effective_scope.project,
        "user": effective_scope.user,
        "coordinator": coordinator,
        "project_identity": {
            "tenant": effective_scope.tenant,
            "project": effective_scope.project,
            "user": effective_scope.user,
            "source": if config.is_some() { "project_config_with_cli_overrides" } else { "cli_scope" }
        },
        "project_config": config,
        "bundle": inspection,
        "discovered_environments": discovered_environments,
        "active_process": active_process,
        "processes": process_report.get("processes").cloned().unwrap_or_else(|| json!([])),
        "attached_nodes": attached_nodes,
        "quota_posture": quota_posture,
        "coordinator_response": coordinator_response,
    }))
}

pub(crate) fn project_list_report(args: ProjectListArgs, cwd: PathBuf) -> Result<Value> {
    let stored_session = read_cli_session(&cwd)?;
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
    let user = session_or_effective_scope_value(
        stored_session.as_ref(),
        &args.scope.user,
        |session| session.user.as_str(),
        "user",
    );
    if let Some(coordinator) = &coordinator {
        let mut session = JsonLineSession::connect(coordinator)?;
        let request = authenticated_or_local_trusted_request(
            coordinator,
            stored_session.as_ref(),
            CoordinatorRequest::ListProjects {
                tenant: tenant.clone(),
                actor_user: user.clone(),
            },
        )?;
        let response = session.request(request)?;
        let projects = match &response {
            CoordinatorResponse::Projects { projects, .. } => projects,
            _ => anyhow::bail!("coordinator returned an unexpected project-list response"),
        };
        let project_count = projects.len();
        return Ok(json!({
            "command": "project list",
            "source": "public_coordinator_api",
            "coordinator": coordinator,
            "tenant": tenant,
            "user": user,
            "projects": projects,
            "project_count": project_count,
            "external_website_required": false,
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    let projects = read_project_config(&cwd)?.into_iter().collect::<Vec<_>>();
    let project_count = projects.len();
    Ok(json!({
        "command": "project list",
        "source": "local_project_config",
        "projects": projects,
        "project_count": project_count,
        "external_website_required": false,
    }))
}

pub(crate) fn project_select_report(args: ProjectSelectArgs, cwd: PathBuf) -> Result<Value> {
    let stored_session = read_cli_session(&cwd)?;
    let tenant = session_or_effective_scope_value(
        stored_session.as_ref(),
        &args.scope.tenant,
        |session| session.tenant.as_str(),
        "tenant",
    );
    let user = session_or_effective_scope_value(
        stored_session.as_ref(),
        &args.scope.user,
        |session| session.user.as_str(),
        "user",
    );
    let coordinator = args.scope.coordinator.clone().or_else(|| {
        stored_session
            .as_ref()
            .map(|session| session.coordinator.clone())
    });
    let config = ProjectConfig {
        tenant: tenant.clone(),
        project: args.selected_project.clone(),
        user: user.clone(),
        coordinator: coordinator.clone(),
    };
    let coordinator_response = if let Some(coordinator) = &coordinator {
        let mut session = JsonLineSession::connect(coordinator)?;
        let request = authenticated_or_local_trusted_request(
            coordinator,
            stored_session.as_ref(),
            CoordinatorRequest::SelectProject {
                tenant: tenant.clone(),
                actor_user: user.clone(),
                project: args.selected_project.clone(),
            },
        )?;
        Some(session.request(request)?)
    } else {
        None
    };
    let selected_project = match coordinator_response.as_ref() {
        Some(CoordinatorResponse::ProjectSelected { project, .. }) => {
            if let Some(mut selected_session) = stored_session.clone() {
                selected_session.project = project.id.as_str().to_owned();
                write_cli_session(&cwd, &selected_session)?;
            }
            serde_json::to_value(project)?
        }
        Some(_) => anyhow::bail!("coordinator returned an unexpected project-select response"),
        None => json!({
            "id": config.project.clone(),
            "tenant": config.tenant.clone(),
            "name": config.project.clone(),
        }),
    };
    write_project_config(&cwd, &config)?;
    Ok(json!({
        "command": "project select",
        "source": if coordinator.is_some() { "public_coordinator_api" } else { "local_project_config" },
        "selected_project": selected_project,
        "project_config_written": true,
        "external_website_required": false,
        "project_config": config,
        "coordinator_response": coordinator_response,
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
