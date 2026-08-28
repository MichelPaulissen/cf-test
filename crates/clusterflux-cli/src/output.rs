use anyhow::Result;
use serde::Serialize;
use serde_json::{json, Value};

use crate::guidance::{ensure_report_guidance, OperationGuidance};

pub(crate) fn emit_report<T: Serialize>(report: &T, json_output: bool) -> Result<()> {
    let mut value = serde_json::to_value(report)?;
    ensure_report_guidance(&mut value)?;
    let exit_code = apply_command_report_exit_code(&mut value);
    if json_output {
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("{}", human_report(&value));
    }
    if let Some(exit_code) = exit_code {
        std::process::exit(exit_code);
    }
    Ok(())
}

pub(crate) fn human_report(value: &Value) -> String {
    let mut lines = Vec::new();
    let has_operation_guidance = value.get("guidance").is_some_and(Value::is_object);
    let title = value
        .get("command")
        .and_then(Value::as_str)
        .map(|command| format!("Clusterflux {command}"))
        .or_else(|| {
            if value.get("human_flow").is_some() || value.pointer("/plan/human_flow").is_some() {
                Some("Clusterflux login".to_owned())
            } else if value.get("metadata").is_some()
                && value.get("source_provider_manifest").is_some()
            {
                Some("Clusterflux bundle inspect".to_owned())
            } else if value.get("entry").is_some() && value.get("session").is_some() {
                Some("Clusterflux run".to_owned())
            } else if value.get("capabilities").is_some() && value.get("node").is_some() {
                Some("Clusterflux node attach".to_owned())
            } else if value.get("public_key_fingerprint").is_some() {
                Some("Clusterflux agent enroll".to_owned())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "Clusterflux report".to_owned());
    lines.push(title);

    push_string_field(&mut lines, value, "status", "status");
    push_string_field(&mut lines, value, "coordinator", "coordinator");
    push_string_field(&mut lines, value, "active_coordinator", "coordinator");
    push_string_field(&mut lines, value, "tenant", "tenant");
    push_string_field(&mut lines, value, "project", "project");
    push_string_field(&mut lines, value, "process", "process");
    push_string_field(&mut lines, value, "active_process", "active process");
    push_string_field(&mut lines, value, "node", "node");
    push_string_field(&mut lines, value, "artifact", "artifact");
    push_string_field(&mut lines, value, "entry", "entry");
    push_string_field(&mut lines, value, "quota_tier", "quota tier");
    push_string_field(&mut lines, value, "config_file", "config");
    push_string_field(&mut lines, value, "adapter", "adapter");

    if let Some(project) = value.get("project").and_then(Value::as_str) {
        if !lines
            .iter()
            .any(|line| line == &format!("project: {project}"))
        {
            lines.push(format!("project: {project}"));
        }
    }
    if let Some(project_config) = value.get("project_config").or_else(|| value.get("project")) {
        if project_config.is_object() {
            push_nested_string_field(&mut lines, project_config, "tenant", "tenant");
            push_nested_string_field(&mut lines, project_config, "project", "project");
            push_nested_string_field(&mut lines, project_config, "coordinator", "coordinator");
        }
    }
    if let Some(link) = value.get("current_directory_link") {
        if link
            .get("links_current_directory")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            lines.push("current directory linked: true".to_owned());
        }
        push_nested_string_field(&mut lines, link, "config_file", "current directory config");
    }
    if let Some(metadata) = value.get("metadata") {
        push_nested_string_field(&mut lines, metadata, "identity", "bundle");
        if let Some(environments) = metadata.get("environments").and_then(Value::as_array) {
            let names = environments
                .iter()
                .filter_map(|env| env.get("name").and_then(Value::as_str))
                .collect::<Vec<_>>();
            if !names.is_empty() {
                lines.push(format!("environments: {}", names.join(", ")));
            }
        }
    }
    if let Some(bundle) = value.get("bundle") {
        if let Some(metadata) = bundle.get("metadata") {
            push_nested_string_field(&mut lines, metadata, "identity", "bundle");
        }
    }
    if let Some(environments) = value
        .get("discovered_environments")
        .and_then(Value::as_array)
    {
        let names = environments
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        if !names.is_empty() {
            lines.push(format!("environments: {}", names.join(", ")));
        }
    }
    if let Some(attached_nodes) = value.get("attached_nodes") {
        if let Some(count) = attached_nodes.get("count").and_then(Value::as_u64) {
            let online = attached_nodes
                .get("online")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            lines.push(format!("attached nodes: {count} ({online} online)"));
        }
    }
    if let Some(current_usage) = value.pointer("/quota_posture/current_usage") {
        lines.push(format!("quota usage: {}", compact_json(current_usage)));
    }
    if let Some(current_task_count) = value.get("current_task_count").and_then(Value::as_u64) {
        lines.push(format!("tasks: {current_task_count}"));
    }
    if let Some(tasks) = value.get("current_tasks").and_then(Value::as_array) {
        push_task_placement_reasons(&mut lines, tasks);
        push_task_locality_failures(&mut lines, tasks);
    }
    if let Some(tasks) = value.get("tasks").and_then(Value::as_array) {
        lines.push(format!("tasks: {}", tasks.len()));
        push_task_placement_reasons(&mut lines, tasks);
        push_task_locality_failures(&mut lines, tasks);
    }
    if let Some(log_entries) = value.get("log_entries").and_then(Value::as_array) {
        lines.push(format!("log entries: {}", log_entries.len()));
    }
    if let Some(artifacts) = value.get("artifacts").and_then(Value::as_array) {
        lines.push(format!("artifacts: {}", artifacts.len()));
    }
    if let Some(statuses) = value
        .get("source_provider_statuses")
        .and_then(Value::as_array)
    {
        push_source_provider_statuses(&mut lines, statuses);
    }
    if let Some(bundle_statuses) = value
        .pointer("/bundle/source_provider_statuses")
        .and_then(Value::as_array)
    {
        push_source_provider_statuses(&mut lines, bundle_statuses);
    }
    if let Some(diagnostics) = value
        .get("pre_schedule_diagnostics")
        .or_else(|| value.get("diagnostics"))
        .and_then(Value::as_array)
    {
        push_cli_diagnostics(&mut lines, diagnostics);
    }
    if let Some(bundle_diagnostics) = value
        .pointer("/bundle/pre_schedule_diagnostics")
        .and_then(Value::as_array)
    {
        push_cli_diagnostics(&mut lines, bundle_diagnostics);
    }
    if let Some(current_usage) = value.get("current_usage") {
        lines.push(format!("quota usage: {}", compact_json(current_usage)));
    }
    if let Some(next_blocked_action) = value.get("next_blocked_action") {
        if !next_blocked_action.is_null() {
            lines.push(format!(
                "next blocked action: {}",
                compact_json(next_blocked_action)
            ));
        }
    }
    push_machine_error_line(
        &mut lines,
        value.get("machine_error"),
        !has_operation_guidance,
    );
    push_machine_error_line(
        &mut lines,
        value.pointer("/run_start/machine_error"),
        !has_operation_guidance,
    );
    push_machine_error_line(
        &mut lines,
        value.pointer("/download_session/machine_error"),
        !has_operation_guidance,
    );
    push_machine_error_line(
        &mut lines,
        value.pointer("/export_plan/machine_error"),
        !has_operation_guidance,
    );
    push_machine_error_line(
        &mut lines,
        value.pointer("/local_export/machine_error"),
        !has_operation_guidance,
    );
    push_machine_error_line(
        &mut lines,
        value.pointer("/local_export/download_session/machine_error"),
        !has_operation_guidance,
    );
    push_machine_error_line(
        &mut lines,
        value.pointer("/local_export/stream/machine_error"),
        !has_operation_guidance,
    );
    if let Some(flow) = value.get("human_flow") {
        if let Some(browser) = flow.get("Browser") {
            lines.push("flow: browser".to_owned());
            push_nested_string_field(&mut lines, browser, "authorization_url", "open");
        }
    }
    if let Some(session) = value.get("session") {
        lines.push(format!("session: {}", compact_json(session)));
    }
    if let Some(account) = value.get("coordinator_account_status") {
        if let Some(checked) = account.get("checked").and_then(Value::as_bool) {
            lines.push(format!("account status checked: {checked}"));
        }
        push_nested_string_field(&mut lines, account, "account_status", "account status");
        if let Some(suspended) = account.get("suspended").and_then(Value::as_bool) {
            lines.push(format!("account suspended: {suspended}"));
        }
        if let Some(disabled) = account.get("disabled").and_then(Value::as_bool) {
            lines.push(format!("account disabled: {disabled}"));
        }
        if let Some(deleted) = account.get("deleted").and_then(Value::as_bool) {
            lines.push(format!("account deleted: {deleted}"));
        }
        if let Some(manual_review) = account.get("manual_review").and_then(Value::as_bool) {
            lines.push(format!("account manual review: {manual_review}"));
        }
        push_nested_string_field(&mut lines, account, "sanitized_reason", "account reason");
        if let Some(exposed) = account
            .get("sensitive_moderation_details_exposed")
            .and_then(Value::as_bool)
        {
            lines.push(format!("sensitive moderation details exposed: {exposed}"));
        }
    }
    if let Some(coordinator_selection) = value.get("coordinator") {
        if coordinator_selection.is_object() {
            lines.push(format!(
                "coordinator: {}",
                compact_json(coordinator_selection)
            ));
        }
    }
    if let Some(reachability) = value.get("coordinator_reachability") {
        if let Some(status) = reachability.get("status").and_then(Value::as_str) {
            lines.push(format!("coordinator reachability: {status}"));
        }
        if let Some(error) = reachability.get("error").and_then(Value::as_str) {
            lines.push(format!("coordinator error: {error}"));
        }
        if let Some(response_type) = reachability
            .pointer("/response/type")
            .and_then(Value::as_str)
        {
            lines.push(format!("coordinator ping: {response_type}"));
        }
    }
    if let Some(response) = value
        .get("response")
        .or_else(|| value.get("coordinator_response"))
    {
        if let Some(response_type) = response.get("type").and_then(Value::as_str) {
            lines.push(format!("coordinator response: {response_type}"));
        }
        if let Some(nodes) = response.get("nodes").and_then(Value::as_array) {
            push_node_drain_summaries(&mut lines, nodes, value.get("node").and_then(Value::as_str));
        }
    }
    if let Some(events) = value
        .pointer("/events/response/events")
        .and_then(Value::as_array)
    {
        lines.push(format!("events: {}", events.len()));
    }
    if let Some(events) = value
        .pointer("/coordinator_response/response/events")
        .and_then(Value::as_array)
    {
        lines.push(format!("events: {}", events.len()));
    }
    if let Some(requires_confirmation) = value.get("requires_confirmation").and_then(Value::as_bool)
    {
        lines.push(format!(
            "confirmation: {}",
            if requires_confirmation {
                "required"
            } else {
                "confirmed"
            }
        ));
    }
    if let Some(flag) = value
        .get("external_website_required")
        .and_then(Value::as_bool)
    {
        lines.push(format!("external website required: {flag}"));
    }
    if let Some(guidance) = value
        .get("guidance")
        .filter(|guidance| guidance.is_object())
    {
        push_operation_guidance(&mut lines, guidance);
    }
    if !has_operation_guidance {
        if let Some(next_actions) = value.get("next_actions").and_then(Value::as_array) {
            let actions = next_actions
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            if !actions.is_empty() {
                lines.push(format!("next: {}", actions.join("; ")));
            }
        }
    }
    if let Some(auth) = value.get("auth").or_else(|| value.get("session")) {
        if let Some(kind) = auth.get("kind").and_then(Value::as_str) {
            lines.push(format!("auth: {kind}"));
        }
        if let Some(authenticated) = auth.get("authenticated").and_then(Value::as_bool) {
            lines.push(format!("authenticated: {authenticated}"));
        }
        if let Some(expires) = auth.get("expires_at").and_then(Value::as_str) {
            lines.push(format!("token expiry: {expires}"));
        } else if let Some(posture) = auth.get("token_expiry_posture").and_then(Value::as_str) {
            lines.push(format!("token expiry: {posture}"));
        } else if auth.get("authenticated").is_some() {
            lines.push("token expiry: unavailable".to_owned());
        }
    }
    if let Some(dependencies) = value.get("dependencies").and_then(Value::as_object) {
        let mut entries = dependencies
            .iter()
            .map(|(name, available)| {
                format!(
                    "{name}={}",
                    if available.as_bool().unwrap_or(false) {
                        "ok"
                    } else {
                        "missing"
                    }
                )
            })
            .collect::<Vec<_>>();
        entries.sort();
        if !entries.is_empty() {
            lines.push(format!("dependencies: {}", entries.join(", ")));
        }
    }
    if let Some(readiness) = value.get("node_readiness") {
        push_nested_string_field(&mut lines, readiness, "os", "node os");
        push_nested_string_field(&mut lines, readiness, "arch", "node arch");
        if let Some(capabilities) = readiness.get("capabilities").and_then(Value::as_array) {
            let caps = capabilities
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            if !caps.is_empty() {
                lines.push(format!("node capabilities: {}", caps.join(", ")));
            }
        }
    }
    if let Some(summary) = value.get("node_readiness_summary") {
        push_nested_string_field(&mut lines, summary, "status", "node readiness");
        if let Some(missing) = summary
            .get("missing_local_dependencies")
            .and_then(Value::as_array)
        {
            let missing = missing.iter().filter_map(Value::as_str).collect::<Vec<_>>();
            if !missing.is_empty() {
                lines.push(format!("node missing dependencies: {}", missing.join(", ")));
            }
        }
        if let Some(actions) = summary.get("next_actions").and_then(Value::as_array) {
            let actions = actions.iter().filter_map(Value::as_str).collect::<Vec<_>>();
            if !actions.is_empty() {
                lines.push(format!("node next: {}", actions.join("; ")));
            }
        }
    }
    if let Some(detection) = value
        .pointer("/plan/detection")
        .or_else(|| value.get("detection"))
    {
        push_node_attach_detection(&mut lines, detection);
    }
    if let Some(disclosures) = value
        .get("grant_disclosures")
        .and_then(Value::as_array)
        .filter(|disclosures| !disclosures.is_empty())
    {
        for disclosure in disclosures {
            let grant = disclosure
                .get("grant")
                .and_then(Value::as_str)
                .unwrap_or("capability");
            let description = disclosure
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("capability grant");
            let policy = if disclosure
                .get("coordinator_policy_limited")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                "policy-limited"
            } else {
                "unbounded"
            };
            lines.push(format!("grant {grant}: {description} ({policy})"));
        }
    }

    lines.dedup();
    lines.join("\n")
}

fn push_node_drain_summaries(lines: &mut Vec<String>, nodes: &[Value], requested: Option<&str>) {
    for node in nodes {
        let Some(id) = node.get("id").and_then(Value::as_str) else {
            continue;
        };
        if requested.is_some_and(|requested| requested != id) {
            continue;
        }
        let availability = if node.get("online").and_then(Value::as_bool) == Some(true) {
            "online"
        } else {
            "offline"
        };
        lines.push(format!("node {id}: {availability}"));
        let Some(drain) = node.get("drain").filter(|drain| drain.is_object()) else {
            continue;
        };
        let state = drain
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let running = drain
            .get("running_task_count")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let queued = drain
            .get("queued_task_count")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let transfers = drain
            .get("active_transfer_count")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let retained = drain
            .get("retained_bytes")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        lines.push(format!(
            "  drain: {state}; {running} running, {queued} queued, {transfers} transfer(s), {retained} retained byte(s)"
        ));
        if let Some(deadline) = drain
            .get("soft_drain_deadline_epoch_seconds")
            .and_then(Value::as_u64)
        {
            lines.push(format!("  soft drain deadline: {deadline}"));
        }
        if let Some(deadline) = drain
            .get("hard_drain_deadline_epoch_seconds")
            .or_else(|| drain.get("provider_deadline_epoch_seconds"))
            .and_then(Value::as_u64)
        {
            lines.push(format!("  hard drain deadline: {deadline}"));
        }
        if drain
            .get("hard_deadline_reached")
            .or_else(|| drain.get("provider_deadline_reached"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            lines.push(
                "  hard deadline reached: remaining work and local retention will be terminated on finalization"
                    .to_owned(),
            );
        }
        if let Some(reason) = drain.get("release_reason").and_then(Value::as_str) {
            lines.push(format!("  release reason: {reason}"));
        }
        if let Some(blockers) = drain.get("blockers").and_then(Value::as_array) {
            for blocker in blockers {
                if let Some(summary) = blocker.get("summary").and_then(Value::as_str) {
                    lines.push(format!("  blocker: {summary}"));
                }
            }
        }
    }
}

fn push_node_attach_detection(lines: &mut Vec<String>, detection: &Value) {
    push_nested_string_field(lines, detection, "os", "node os");
    push_nested_string_field(lines, detection, "arch", "node arch");
    push_nested_string_field(lines, detection, "command_backend", "command backend");
    if let Some(backend) = detection.get("container_backend").and_then(Value::as_str) {
        let available = detection
            .get("container_backend_available")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        lines.push(format!(
            "container backend: {backend} ({})",
            if available { "available" } else { "reported" }
        ));
    } else if detection
        .get("container_backend_reported")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        lines.push("container backend: reported".to_owned());
    }
    if let Some(providers) = detection
        .get("source_provider_backends")
        .and_then(Value::as_array)
    {
        let entries = providers
            .iter()
            .filter_map(|provider| {
                let name = provider.get("provider").and_then(Value::as_str)?;
                let state = if provider
                    .get("available")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    "available"
                } else {
                    "detected"
                };
                Some(format!("{name}={state}"))
            })
            .collect::<Vec<_>>();
        if !entries.is_empty() {
            lines.push(format!("source providers: {}", entries.join(", ")));
        }
    }
    if let Some(overrides) = detection
        .get("manual_capability_overrides")
        .and_then(Value::as_array)
    {
        let overrides = overrides
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        if !overrides.is_empty() {
            lines.push(format!("capability overrides: {}", overrides.join(", ")));
        }
    }
}

fn push_string_field(lines: &mut Vec<String>, value: &Value, key: &str, label: &str) {
    if let Some(text) = value.get(key).and_then(Value::as_str) {
        lines.push(format!("{label}: {text}"));
    } else if let Some(path) = value.get(key).and_then(|value| {
        value
            .as_object()
            .and_then(|object| object.get("display"))
            .and_then(Value::as_str)
    }) {
        lines.push(format!("{label}: {path}"));
    }
}

fn push_task_placement_reasons(lines: &mut Vec<String>, tasks: &[Value]) {
    for task in tasks {
        let Some(placement) = task.get("node_placement") else {
            continue;
        };
        let Some(reasons) = placement.get("reasons").and_then(Value::as_array) else {
            continue;
        };
        let reasons = reasons.iter().filter_map(Value::as_str).collect::<Vec<_>>();
        if reasons.is_empty() {
            continue;
        }
        let task_name = task
            .get("task")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let node = placement
            .get("node")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        lines.push(format!(
            "placement {task_name}: {node} ({})",
            reasons.join(", ")
        ));
    }
}

fn push_task_locality_failures(lines: &mut Vec<String>, tasks: &[Value]) {
    for task in tasks {
        let Some(locality) = task.get("locality_failure") else {
            continue;
        };
        if locality.is_null() {
            continue;
        }
        let task_name = task
            .get("task")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let affected = locality
            .get("affected_data")
            .and_then(Value::as_str)
            .unwrap_or("direct_transfer");
        let reason = locality
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("direct transfer or locality failed");
        lines.push(format!("locality {task_name}: {affected} ({reason})"));
        let actions = locality
            .get("safe_next_actions")
            .and_then(Value::as_array)
            .map(|actions| actions.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        if !actions.is_empty() {
            lines.push(format!("locality next {task_name}: {}", actions.join("; ")));
        }
    }
}

fn push_nested_string_field(lines: &mut Vec<String>, value: &Value, key: &str, label: &str) {
    if let Some(text) = value.get(key).and_then(Value::as_str) {
        lines.push(format!("{label}: {text}"));
    }
}

fn push_machine_error_line(
    lines: &mut Vec<String>,
    machine_error: Option<&Value>,
    include_legacy_actions: bool,
) {
    let Some(machine_error) = machine_error else {
        return;
    };
    if machine_error.is_null() {
        return;
    }
    let category = machine_error
        .get("category")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let exit_code = machine_error
        .get("stable_exit_code")
        .and_then(Value::as_i64)
        .unwrap_or(1);
    lines.push(format!("error category: {category} (exit {exit_code})"));
    if let Some(tier) = machine_error
        .get("community_tier_label")
        .and_then(Value::as_str)
    {
        lines.push(format!("quota tier: {tier}"));
    }
    if include_legacy_actions {
        if let Some(next_actions) = machine_error.get("next_actions").and_then(Value::as_array) {
            let actions = next_actions
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            if !actions.is_empty() {
                lines.push(format!("error next: {}", actions.join("; ")));
            }
        }
    }
}

fn push_operation_guidance(lines: &mut Vec<String>, value: &Value) {
    let Ok(guidance) = serde_json::from_value::<OperationGuidance>(value.clone()) else {
        lines.push("next: unavailable (invalid operation guidance)".to_owned());
        return;
    };
    if let Some(command) = guidance.recommended {
        lines.push(format!(
            "next: {}{}",
            command.shell_command(),
            guidance_annotations(command.mutating, command.requires_confirmation)
        ));
    } else if let Some(reason) = guidance.no_safe_action_reason {
        lines.push(format!("next: none ({reason})"));
    }
    for command in guidance.alternatives {
        lines.push(format!(
            "alternative: {}{}",
            command.shell_command(),
            guidance_annotations(command.mutating, command.requires_confirmation)
        ));
    }
}

fn guidance_annotations(mutating: bool, requires_confirmation: bool) -> String {
    let mut annotations = Vec::new();
    if mutating {
        annotations.push("mutating");
    }
    if requires_confirmation {
        annotations.push("confirmation required");
    }
    if annotations.is_empty() {
        String::new()
    } else {
        format!(" [{}]", annotations.join(", "))
    }
}

fn push_source_provider_statuses(lines: &mut Vec<String>, statuses: &[Value]) {
    let entries = statuses
        .iter()
        .filter_map(|status| {
            let provider = status.get("provider").and_then(Value::as_str)?;
            let state = status.get("status").and_then(Value::as_str)?;
            let active = status
                .get("active")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            Some(format!(
                "{provider}={state}{}",
                if active { "(active)" } else { "" }
            ))
        })
        .collect::<Vec<_>>();
    if !entries.is_empty() {
        lines.push(format!("source providers: {}", entries.join(", ")));
    }
}

fn push_cli_diagnostics(lines: &mut Vec<String>, diagnostics: &[Value]) {
    if diagnostics.is_empty() {
        return;
    }
    lines.push(format!("diagnostics: {}", diagnostics.len()));
    for diagnostic in diagnostics.iter().take(3) {
        let severity = diagnostic
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("info");
        let message = diagnostic
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("diagnostic");
        lines.push(format!("diagnostic {severity}: {message}"));
    }
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<unprintable>".to_owned())
}

pub(crate) fn apply_command_report_exit_code(value: &mut Value) -> Option<i32> {
    for pointer in [
        "/machine_error",
        "/run_start/machine_error",
        "/restart_request/machine_error",
        "/cancel_request/machine_error",
        "/task_restart/machine_error",
        "/download_session/machine_error",
        "/export_plan/machine_error",
        "/local_export/machine_error",
        "/local_export/download_session/machine_error",
        "/local_export/stream/machine_error",
    ] {
        let Some(machine_error) = value.pointer_mut(pointer) else {
            continue;
        };
        let Some(exit_code) = machine_error
            .get("stable_exit_code")
            .and_then(Value::as_i64)
            .and_then(|code| i32::try_from(code).ok())
            .filter(|code| *code != 0)
        else {
            continue;
        };
        if let Some(object) = machine_error.as_object_mut() {
            object.insert("process_exit_code_applied".to_owned(), json!(true));
        }
        return Some(exit_code);
    }
    None
}

#[cfg(test)]
mod guidance_tests {
    use super::*;
    use crate::guidance::{GuidanceKind, GuidedCommand, OperationGuidance};

    #[test]
    fn human_report_renders_typed_guidance_and_hides_legacy_actions() {
        let guidance = OperationGuidance::recommended(GuidedCommand::new(
            GuidanceKind::Authenticate,
            ["clusterflux", "login", "--browser"],
            true,
            false,
        ))
        .alternative(GuidedCommand::new(
            GuidanceKind::Inspect,
            ["clusterflux", "auth", "status"],
            false,
            false,
        ))
        .build()
        .unwrap();
        let report = json!({
            "command": "run",
            "status": "authentication_required",
            "machine_error": {
                "category": "authentication",
                "stable_exit_code": 20,
                "next_actions": ["legacy error action"]
            },
            "next_actions": ["legacy top-level action"],
            "guidance": guidance,
        });

        let human = human_report(&report);
        assert!(human.contains("error category: authentication (exit 20)"));
        assert!(human.contains("next: clusterflux login --browser [mutating]"));
        assert!(human.contains("alternative: clusterflux auth status"));
        assert!(!human.contains("legacy error action"));
        assert!(!human.contains("legacy top-level action"));
    }

    #[test]
    fn human_report_quotes_structured_commands() {
        let report = json!({
            "command": "process status",
            "guidance": {
                "recommended": {
                    "kind": "inspect",
                    "command": ["clusterflux", "process", "status", "--process", "process with spaces"],
                    "mutating": false,
                    "requires_confirmation": false
                },
                "alternatives": []
            }
        });

        assert!(human_report(&report)
            .contains("next: clusterflux process status --process 'process with spaces'"));
    }

    #[test]
    fn human_report_explains_when_no_safe_action_exists() {
        let report = json!({
            "command": "logs",
            "guidance": {
                "recommended": null,
                "alternatives": [],
                "no_safe_action_reason": "operation completed; no follow-up is required"
            }
        });

        assert!(human_report(&report)
            .contains("next: none (operation completed; no follow-up is required)"));
    }
}
