use std::collections::BTreeSet;
use std::fmt;

use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Cli;

/// A machine-readable CLI operation that is useful after the current result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GuidanceKind {
    Authenticate,
    Inspect,
    Wait,
    Retry,
    Configure,
    Mutate,
}

/// One executable next action. `command` is argv, not a shell command string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuidedCommand {
    pub(crate) kind: GuidanceKind,
    pub(crate) command: Vec<String>,
    pub(crate) mutating: bool,
    pub(crate) requires_confirmation: bool,
}

impl GuidedCommand {
    pub(crate) fn new(
        kind: GuidanceKind,
        command: impl IntoIterator<Item = impl Into<String>>,
        mutating: bool,
        requires_confirmation: bool,
    ) -> Self {
        Self {
            kind,
            command: command.into_iter().map(Into::into).collect(),
            mutating,
            requires_confirmation,
        }
    }

    pub(crate) fn shell_command(&self) -> String {
        self.command
            .iter()
            .map(|argument| shell_quote(argument))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Stable guidance attached to a CLI report.
///
/// Exactly one of `recommended` and `no_safe_action_reason` is present.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationGuidance {
    pub(crate) recommended: Option<GuidedCommand>,
    pub(crate) alternatives: Vec<GuidedCommand>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) no_safe_action_reason: Option<String>,
}

impl OperationGuidance {
    pub(crate) fn recommended(command: GuidedCommand) -> GuidanceBuilder {
        GuidanceBuilder {
            recommended: Some(command),
            alternatives: Vec::new(),
            no_safe_action_reason: None,
        }
    }

    pub(crate) fn no_safe_action(reason: impl Into<String>) -> GuidanceBuilder {
        GuidanceBuilder {
            recommended: None,
            alternatives: Vec::new(),
            no_safe_action_reason: Some(reason.into()),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GuidanceBuilder {
    recommended: Option<GuidedCommand>,
    alternatives: Vec<GuidedCommand>,
    no_safe_action_reason: Option<String>,
}

impl GuidanceBuilder {
    pub(crate) fn alternative(mut self, command: GuidedCommand) -> Self {
        self.alternatives.push(command);
        self
    }

    pub(crate) fn build(self) -> Result<OperationGuidance, GuidanceError> {
        let has_recommended = self.recommended.is_some();
        let has_reason = self
            .no_safe_action_reason
            .as_deref()
            .is_some_and(|reason| !reason.trim().is_empty());
        if has_recommended == has_reason {
            return Err(GuidanceError::InvalidState(
                "exactly one of recommended and no_safe_action_reason must be present".to_owned(),
            ));
        }

        if let Some(command) = &self.recommended {
            validate_guided_command(command)?;
        }

        let mut seen = BTreeSet::new();
        if let Some(command) = &self.recommended {
            seen.insert(command.command.clone());
        }
        let mut alternatives = Vec::new();
        for command in self.alternatives {
            validate_guided_command(&command)?;
            if seen.insert(command.command.clone()) {
                alternatives.push(command);
            }
        }

        Ok(OperationGuidance {
            recommended: self.recommended,
            alternatives,
            no_safe_action_reason: self.no_safe_action_reason,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GuidanceError {
    InvalidState(String),
    InvalidCommand(String),
    ReportIsNotObject,
}

impl fmt::Display for GuidanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState(message) => write!(formatter, "invalid CLI guidance: {message}"),
            Self::InvalidCommand(message) => {
                write!(formatter, "invalid guided CLI command: {message}")
            }
            Self::ReportIsNotObject => formatter.write_str("CLI report is not a JSON object"),
        }
    }
}

impl std::error::Error for GuidanceError {}

pub(crate) fn attach_guidance(
    report: &mut Value,
    guidance: OperationGuidance,
) -> Result<(), GuidanceError> {
    let object = report
        .as_object_mut()
        .ok_or(GuidanceError::ReportIsNotObject)?;
    object.insert(
        "guidance".to_owned(),
        serde_json::to_value(guidance).map_err(|error| {
            GuidanceError::InvalidState(format!("serialize operation guidance: {error}"))
        })?,
    );
    Ok(())
}

/// Ensure every emitted command report has one stable guidance state.
///
/// Individual commands should attach richer guidance when they know more. This
/// fallback covers shared asynchronous and failure shapes, then makes terminal
/// success explicit instead of inventing work for the caller.
pub(crate) fn ensure_report_guidance(report: &mut Value) -> Result<(), GuidanceError> {
    if report.get("guidance").is_some_and(Value::is_object) {
        return Ok(());
    }
    let guidance = guidance_for_report(report)?;
    attach_guidance(report, guidance)
}

fn guidance_for_report(report: &Value) -> Result<OperationGuidance, GuidanceError> {
    if report
        .get("confirmation_required")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let mut builder = OperationGuidance::no_safe_action(
            "review the target before explicitly confirming this mutating operation",
        );
        if let Some(command) = confirmation_command(report) {
            builder = builder.alternative(GuidedCommand::new(
                GuidanceKind::Mutate,
                command,
                true,
                true,
            ));
        }
        return builder.build();
    }

    if let Some(machine_error) = first_machine_error(report) {
        return error_guidance(report, machine_error);
    }

    if report.get("status").and_then(Value::as_str) == Some("requires_coordinator") {
        return OperationGuidance::recommended(scoped_command(
            report,
            GuidanceKind::Inspect,
            ["clusterflux", "doctor"],
            false,
        ))
        .build();
    }

    let command = report.get("command").and_then(Value::as_str).unwrap_or("");
    if command == "run"
        && report
            .pointer("/run_start/accepted")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        if let Some(process) = string_at(report, &["/run_start/process", "/process"]) {
            return wait_process_guidance(report, process, false);
        }
    }
    if matches!(
        command,
        "process restart" | "process cancel" | "task restart"
    ) {
        let accepted = ["/restart_request/accepted", "/cancel_request/accepted"]
            .iter()
            .any(|pointer| report.pointer(pointer).and_then(Value::as_bool) == Some(true));
        if accepted {
            if let Some(process) = string_at(
                report,
                &[
                    "/restart_request/process",
                    "/cancel_request/process",
                    "/process",
                ],
            ) {
                return wait_process_guidance(report, process, command == "process cancel");
            }
        }
    }
    if command == "node revoke"
        && report
            .get("credential_revoked")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        if let Some(node) = string_at(report, &["/node"]) {
            return wait_node_guidance(report, node, "gone");
        }
    }
    if command == "runs cancel" {
        if let Some(run) = string_at(report, &["/run/run_id", "/run"]) {
            return wait_run_guidance(report, run, "terminal", true);
        }
    }
    if command == "runs show" {
        let state = report.pointer("/run/state").and_then(Value::as_str);
        if let Some(run) = string_at(report, &["/run/run_id"]) {
            return match state {
                Some("failed" | "cancelled") => OperationGuidance::recommended(scoped_command(
                    report,
                    GuidanceKind::Inspect,
                    ["clusterflux", "runs", "diagnose", run],
                    false,
                ))
                .build(),
                Some("completed") => OperationGuidance::no_safe_action(
                    "run completed successfully; no follow-up is required",
                )
                .build(),
                _ => wait_run_guidance(report, run, "terminal", false),
            };
        }
    }
    if command == "runs list" {
        let active = report
            .get("runs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|run| {
                !matches!(
                    run.get("state").and_then(Value::as_str),
                    Some("completed" | "failed" | "cancelled")
                )
            })
            .collect::<Vec<_>>();
        if active.len() == 1 {
            if let Some(run) = active[0].get("run_id").and_then(Value::as_str) {
                return wait_run_guidance(report, run, "terminal", false);
            }
        }
    }
    if command == "process status" {
        let state = report.get("state").and_then(Value::as_str);
        if report
            .get("live_process")
            .is_some_and(|value| !value.is_null())
            && !matches!(state, Some("completed" | "failed" | "cancelled"))
        {
            if let Some(process) = string_at(report, &["/process"]) {
                return wait_process_guidance(report, process, false);
            }
        }
    }
    if command == "process list" {
        let processes = report.get("processes").and_then(Value::as_array);
        if let Some(process) = processes
            .filter(|processes| processes.len() == 1)
            .and_then(|processes| processes[0].get("process"))
            .and_then(Value::as_str)
        {
            return wait_process_guidance(report, process, false);
        }
    }
    if command == "process abort" {
        if let Some(process) = string_at(report, &["/process"]) {
            return OperationGuidance::recommended(scoped_command(
                report,
                GuidanceKind::Inspect,
                ["clusterflux", "process", "status", "--process", process],
                false,
            ))
            .build();
        }
    }
    if command == "artifact export"
        && report
            .pointer("/export_plan/status")
            .and_then(Value::as_str)
            == Some("transfer_created")
    {
        let mut base = vec!["clusterflux", "artifact", "list"];
        if let Some(process) = string_at(report, &["/export_plan/process"]) {
            base.extend(["--process", process]);
        }
        return OperationGuidance::recommended(scoped_command(
            report,
            GuidanceKind::Inspect,
            base,
            false,
        ))
        .build();
    }
    if command == "node enroll" {
        return OperationGuidance::no_safe_action(
            "the enrollment grant was returned separately and is intentionally never copied into guidance",
        )
        .build();
    }
    if command == "node attach" {
        return OperationGuidance::no_safe_action(
            "node identity is attached; start the node worker in its own terminal before waiting for readiness",
        )
        .build();
    }
    if matches!(command, "key add" | "key revoke") {
        return OperationGuidance::recommended(scoped_command(
            report,
            GuidanceKind::Inspect,
            ["clusterflux", "key", "list"],
            false,
        ))
        .build();
    }
    if matches!(command, "project init" | "project select") {
        return OperationGuidance::recommended(scoped_command(
            report,
            GuidanceKind::Inspect,
            ["clusterflux", "project", "status"],
            false,
        ))
        .build();
    }
    if command.starts_with("wait ") {
        return OperationGuidance::no_safe_action(
            "the requested wait condition was satisfied; no follow-up is required",
        )
        .build();
    }
    if command == "build" {
        return OperationGuidance::no_safe_action(
            "the build completed; launching it is an explicit mutating action",
        )
        .alternative(GuidedCommand::new(
            GuidanceKind::Mutate,
            ["clusterflux", "run"],
            true,
            false,
        ))
        .build();
    }
    OperationGuidance::no_safe_action("operation completed; no follow-up is required").build()
}

fn first_machine_error(report: &Value) -> Option<&Value> {
    [
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
        "/coordinator_account_status/machine_error",
        "/server_session_revocation/machine_error",
    ]
    .iter()
    .find_map(|pointer| report.pointer(pointer).filter(|value| value.is_object()))
}

fn error_guidance(
    report: &Value,
    machine_error: &Value,
) -> Result<OperationGuidance, GuidanceError> {
    let category = machine_error
        .get("category")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let command = report.get("command").and_then(Value::as_str).unwrap_or("");
    if command.starts_with("wait ") && matches!(category, "timeout" | "interrupted") {
        if let Some(command) = repeat_wait_command(report) {
            return OperationGuidance::recommended(GuidedCommand::new(
                GuidanceKind::Wait,
                command,
                false,
                false,
            ))
            .build();
        }
    }
    if command.starts_with("wait ")
        && report.get("status").and_then(Value::as_str) == Some("terminal_failure")
    {
        if let Some(run) = string_at(report, &["/run", "/selector/run"]) {
            return OperationGuidance::recommended(scoped_command(
                report,
                GuidanceKind::Inspect,
                ["clusterflux", "runs", "diagnose", run],
                false,
            ))
            .build();
        }
        if let Some(process) = string_at(report, &["/process", "/selector/process"]) {
            return OperationGuidance::recommended(scoped_command(
                report,
                GuidanceKind::Inspect,
                ["clusterflux", "logs", "--process", process],
                false,
            ))
            .build();
        }
    }

    let mut guidance = match category {
        "authentication" => {
            let mut command = vec![
                "clusterflux".to_owned(),
                "login".to_owned(),
                "--browser".to_owned(),
            ];
            if let Some(coordinator) = string_at(report, &["/coordinator", "/target/coordinator"]) {
                command.extend(["--coordinator".to_owned(), coordinator.to_owned()]);
            }
            if let Some(project) = string_at(report, &["/project", "/target/project"]) {
                command.extend(["--project-id".to_owned(), project.to_owned()]);
            }
            OperationGuidance::recommended(GuidedCommand::new(
                GuidanceKind::Authenticate,
                command,
                true,
                false,
            ))
            .build()
        }
        "authorization" => OperationGuidance::recommended(scoped_command(
            report,
            GuidanceKind::Inspect,
            ["clusterflux", "auth", "status"],
            false,
        ))
        .build(),
        "quota" => OperationGuidance::recommended(scoped_command(
            report,
            GuidanceKind::Inspect,
            ["clusterflux", "quota", "status"],
            false,
        ))
        .build(),
        "capability" => {
            let base = if let Some(node) = string_at(report, &["/node", "/target/node"]) {
                vec!["clusterflux", "node", "doctor", "--node", node]
            } else {
                vec!["clusterflux", "node", "list"]
            };
            OperationGuidance::recommended(scoped_command(
                report,
                GuidanceKind::Inspect,
                base,
                false,
            ))
            .build()
        }
        "program" => {
            let mut base = vec!["clusterflux", "logs"];
            if let Some(process) = string_at(report, &["/process", "/target/process"]) {
                base.extend(["--process", process]);
            }
            if let Some(task) = string_at(report, &["/task", "/target/task"]) {
                base.extend(["--task", task]);
            }
            OperationGuidance::recommended(scoped_command(
                report,
                GuidanceKind::Inspect,
                base,
                false,
            ))
            .build()
        }
        "active_process" => {
            let mut base = vec!["clusterflux", "process", "status"];
            if let Some(process) = string_at(report, &["/process", "/active_process"]) {
                base.extend(["--process", process]);
            }
            OperationGuidance::recommended(scoped_command(
                report,
                GuidanceKind::Inspect,
                base,
                false,
            ))
            .build()
        }
        "environment" => OperationGuidance::recommended(GuidedCommand::new(
            GuidanceKind::Inspect,
            ["clusterflux", "inspect"],
            false,
            false,
        ))
        .build(),
        _ => OperationGuidance::recommended(scoped_command(
            report,
            GuidanceKind::Inspect,
            ["clusterflux", "doctor"],
            false,
        ))
        .build(),
    }?;
    merge_coordinator_alternatives(&mut guidance, machine_error)?;
    Ok(guidance)
}

fn merge_coordinator_alternatives(
    guidance: &mut OperationGuidance,
    machine_error: &Value,
) -> Result<(), GuidanceError> {
    let mut seen = BTreeSet::new();
    if let Some(recommended) = &guidance.recommended {
        seen.insert(recommended.command.clone());
    }
    seen.extend(
        guidance
            .alternatives
            .iter()
            .map(|alternative| alternative.command.clone()),
    );
    let Some(actions) = machine_error
        .get("coordinator_next_actions")
        .and_then(Value::as_array)
    else {
        return Ok(());
    };
    for action in actions.iter().filter_map(Value::as_str) {
        let argv = action
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let Some(candidate) = coordinator_alternative(argv) else {
            continue;
        };
        if validate_guided_command(&candidate).is_ok() && seen.insert(candidate.command.clone()) {
            guidance.alternatives.push(candidate);
        }
    }
    Ok(())
}

fn coordinator_alternative(argv: Vec<String>) -> Option<GuidedCommand> {
    if argv.first().map(String::as_str) != Some("clusterflux") {
        return None;
    }
    let mutating = matches!(
        argv.get(1).map(String::as_str),
        Some("run" | "build" | "login" | "logout" | "secret" | "key" | "admin")
    ) || matches!(
        (
            argv.get(1).map(String::as_str),
            argv.get(2).map(String::as_str)
        ),
        (Some("runs"), Some("retry" | "trigger" | "cancel"))
            | (Some("process"), Some("restart" | "cancel" | "abort"))
            | (Some("task"), Some("restart"))
            | (Some("node"), Some("attach" | "enroll" | "revoke"))
            | (Some("project"), Some("init" | "select"))
            | (Some("auth"), Some("logout" | "connect-self-hosted"))
    );
    let kind = match argv.get(1).map(String::as_str) {
        Some("wait") => GuidanceKind::Wait,
        Some("login") => GuidanceKind::Authenticate,
        Some("runs") if argv.get(2).map(String::as_str) == Some("retry") => GuidanceKind::Retry,
        _ if mutating => GuidanceKind::Mutate,
        _ => GuidanceKind::Inspect,
    };
    let requires_confirmation = argv.iter().any(|argument| argument == "--yes");
    Some(GuidedCommand::new(
        kind,
        argv,
        mutating,
        requires_confirmation,
    ))
}

fn wait_process_guidance(
    report: &Value,
    process: &str,
    accept_non_success: bool,
) -> Result<OperationGuidance, GuidanceError> {
    let mut base = vec![
        "clusterflux",
        "wait",
        "process",
        "--process",
        process,
        "--for",
        "terminal",
        "--timeout",
        "30m",
    ];
    if accept_non_success {
        base.push("--accept-non-success");
    }
    OperationGuidance::recommended(scoped_command(report, GuidanceKind::Wait, base, false)).build()
}

fn wait_run_guidance(
    report: &Value,
    run: &str,
    condition: &str,
    accept_non_success: bool,
) -> Result<OperationGuidance, GuidanceError> {
    let mut base = vec![
        "clusterflux",
        "wait",
        "run",
        "--run",
        run,
        "--for",
        condition,
        "--timeout",
        "30m",
    ];
    if accept_non_success {
        base.push("--accept-non-success");
    }
    OperationGuidance::recommended(scoped_command(report, GuidanceKind::Wait, base, false)).build()
}

fn wait_node_guidance(
    report: &Value,
    node: &str,
    condition: &str,
) -> Result<OperationGuidance, GuidanceError> {
    OperationGuidance::recommended(scoped_command(
        report,
        GuidanceKind::Wait,
        [
            "clusterflux",
            "wait",
            "node",
            "--node",
            node,
            "--for",
            condition,
            "--timeout",
            "5m",
        ],
        false,
    ))
    .build()
}

fn scoped_command<'a>(
    report: &Value,
    kind: GuidanceKind,
    base: impl IntoIterator<Item = &'a str>,
    mutating: bool,
) -> GuidedCommand {
    let mut command = base.into_iter().map(str::to_owned).collect::<Vec<_>>();
    append_scope(report, &mut command);
    GuidedCommand::new(kind, command, mutating, false)
}

fn append_scope(report: &Value, command: &mut Vec<String>) {
    for (flag, pointers) in [
        ("--coordinator", ["/coordinator", "/target/coordinator"]),
        ("--tenant", ["/tenant", "/target/tenant"]),
        ("--project-id", ["/project", "/target/project"]),
        ("--user", ["/user", "/target/user"]),
    ] {
        if let Some(value) = string_at(report, &pointers) {
            command.extend([flag.to_owned(), value.to_owned()]);
        }
    }
}

fn string_at<'a>(report: &'a Value, pointers: &[&str]) -> Option<&'a str> {
    pointers
        .iter()
        .find_map(|pointer| report.pointer(pointer).and_then(Value::as_str))
        .filter(|value| !value.is_empty())
}

fn confirmation_command(report: &Value) -> Option<Vec<String>> {
    let command = report.get("command")?.as_str()?;
    let mut argv = match command {
        "process restart" => vec!["clusterflux", "process", "restart"],
        "process cancel" => vec!["clusterflux", "process", "cancel"],
        "process abort" => vec!["clusterflux", "process", "abort"],
        "node revoke" => vec!["clusterflux", "node", "revoke"],
        "task restart" => vec!["clusterflux", "task", "restart"],
        "key revoke" => vec!["clusterflux", "key", "revoke"],
        "logout" => vec!["clusterflux", "logout"],
        "auth logout" => vec!["clusterflux", "auth", "logout"],
        "admin suspend-tenant" => vec!["clusterflux", "admin", "suspend-tenant"],
        _ => return None,
    }
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    if command == "task restart" {
        argv.push(string_at(report, &["/target/task"])?.to_owned());
    }
    for (flag, pointers) in [
        ("--process", ["/target/process", "/process"]),
        ("--node", ["/target/node", "/node"]),
        ("--task", ["/target/task", "/task"]),
        ("--agent", ["/target/agent", "/agent"]),
        (
            "--target-tenant",
            ["/target/target_tenant", "/target_tenant"],
        ),
    ] {
        if command == "task restart" && flag == "--task" {
            continue;
        }
        if let Some(value) = string_at(report, &pointers) {
            argv.extend([flag.to_owned(), value.to_owned()]);
        }
    }
    append_scope(report, &mut argv);
    argv.push("--yes".to_owned());
    Some(argv)
}

fn repeat_wait_command(report: &Value) -> Option<Vec<String>> {
    let command = report.get("command")?.as_str()?;
    let condition = report.get("condition")?.as_str()?;
    let timeout = report.get("timeout_ms")?.as_u64()?.max(1).to_string() + "ms";
    let selector = report.get("selector")?;
    let mut argv = match command {
        "wait run" => {
            if let Some(run) = selector.get("run").and_then(Value::as_str) {
                vec!["clusterflux", "wait", "run", "--run", run]
            } else {
                vec![
                    "clusterflux",
                    "wait",
                    "run",
                    "--repository",
                    selector.get("repository")?.as_str()?,
                    "--commit",
                    selector.get("commit")?.as_str()?,
                ]
            }
        }
        "wait process" => vec![
            "clusterflux",
            "wait",
            "process",
            "--process",
            selector.get("process")?.as_str()?,
        ],
        "wait node" => vec![
            "clusterflux",
            "wait",
            "node",
            "--node",
            selector.get("node")?.as_str()?,
        ],
        _ => return None,
    }
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    argv.extend([
        "--for".to_owned(),
        condition.to_owned(),
        "--timeout".to_owned(),
        timeout,
    ]);
    append_scope(report, &mut argv);
    Some(argv)
}

fn validate_guided_command(command: &GuidedCommand) -> Result<(), GuidanceError> {
    if command.command.first().map(String::as_str) != Some("clusterflux") {
        return Err(GuidanceError::InvalidCommand(
            "argv must begin with `clusterflux`".to_owned(),
        ));
    }
    if command.requires_confirmation && !command.mutating {
        return Err(GuidanceError::InvalidCommand(
            "a confirmation-requiring command must be marked mutating".to_owned(),
        ));
    }
    if command.command.iter().any(|argument| {
        argument.is_empty()
            || argument.contains('<')
            || argument.contains('>')
            || is_secret_bearing_flag(argument)
    }) {
        return Err(GuidanceError::InvalidCommand(
            "argv contains an empty value, placeholder, or secret-bearing option".to_owned(),
        ));
    }
    if command.kind == GuidanceKind::Wait && !has_finite_timeout(&command.command) {
        return Err(GuidanceError::InvalidCommand(
            "wait guidance must include a finite, nonzero --timeout".to_owned(),
        ));
    }
    Cli::try_parse_from(&command.command).map_err(|error| {
        GuidanceError::InvalidCommand(format!("command does not parse: {error}"))
    })?;
    Ok(())
}

fn is_secret_bearing_flag(argument: &str) -> bool {
    let option = argument.split('=').next().unwrap_or(argument);
    matches!(
        option,
        "--session-secret"
            | "--session-token"
            | "--enrollment-grant"
            | "--admin-token"
            | "--private-key"
            | "--token"
    )
}

fn has_finite_timeout(command: &[String]) -> bool {
    command.iter().enumerate().any(|(index, argument)| {
        let timeout = if argument == "--timeout" {
            command.get(index + 1).map(String::as_str)
        } else {
            argument.strip_prefix("--timeout=")
        };
        timeout.is_some_and(|timeout| {
            let timeout = timeout.trim();
            !timeout.is_empty() && !matches!(timeout, "0" | "0s" | "0m" | "0h" | "infinite" | "inf")
        })
    })
}

pub(crate) fn shell_quote(argument: &str) -> String {
    if !argument.is_empty()
        && argument.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-'
                )
        })
    {
        return argument.to_owned();
    }
    format!("'{}'", argument.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guidance_serializes_commands_as_argv_and_deduplicates() {
        let status = GuidedCommand::new(
            GuidanceKind::Inspect,
            [
                "clusterflux",
                "process",
                "status",
                "--process",
                "vp-current",
            ],
            false,
            false,
        );
        let guidance = OperationGuidance::recommended(status.clone())
            .alternative(status)
            .build()
            .unwrap();

        assert!(guidance.alternatives.is_empty());
        assert_eq!(
            serde_json::to_value(guidance).unwrap()["recommended"]["command"],
            serde_json::json!([
                "clusterflux",
                "process",
                "status",
                "--process",
                "vp-current"
            ])
        );
    }

    #[test]
    fn confirmation_requires_a_mutating_command() {
        let error = OperationGuidance::recommended(GuidedCommand::new(
            GuidanceKind::Inspect,
            ["clusterflux", "doctor"],
            false,
            true,
        ))
        .build()
        .unwrap_err();

        assert!(error.to_string().contains("must be marked mutating"));
    }

    #[test]
    fn wait_requires_a_nonzero_timeout() {
        let error = OperationGuidance::recommended(GuidedCommand::new(
            GuidanceKind::Wait,
            ["clusterflux", "doctor"],
            false,
            false,
        ))
        .build()
        .unwrap_err();

        assert!(error.to_string().contains("finite, nonzero --timeout"));
    }

    #[test]
    fn guided_commands_must_parse() {
        let error = OperationGuidance::recommended(GuidedCommand::new(
            GuidanceKind::Inspect,
            ["clusterflux", "not-a-command"],
            false,
            false,
        ))
        .build()
        .unwrap_err();

        assert!(error.to_string().contains("does not parse"));
    }

    #[test]
    fn guidance_rejects_placeholders_and_secret_options() {
        for command in [
            vec!["clusterflux", "node", "status", "--node", "<node-id>"],
            vec![
                "clusterflux",
                "node",
                "attach",
                "--enrollment-grant",
                "secret",
            ],
        ] {
            let error = OperationGuidance::recommended(GuidedCommand::new(
                GuidanceKind::Inspect,
                command,
                false,
                false,
            ))
            .build()
            .unwrap_err();
            assert!(error.to_string().contains("secret-bearing option"));
        }
    }

    #[test]
    fn shell_rendering_quotes_arguments_without_evaluating_them() {
        let command = GuidedCommand::new(
            GuidanceKind::Inspect,
            ["clusterflux", "project", "select", "project with 'quotes'"],
            false,
            false,
        );
        assert_eq!(
            command.shell_command(),
            "clusterflux project select 'project with '\"'\"'quotes'\"'\"''"
        );
    }

    #[test]
    fn no_safe_action_is_explicit() {
        let guidance =
            OperationGuidance::no_safe_action("operation completed; no follow-up is required")
                .build()
                .unwrap();
        assert!(guidance.recommended.is_none());
        assert_eq!(
            guidance.no_safe_action_reason.as_deref(),
            Some("operation completed; no follow-up is required")
        );
    }

    #[test]
    fn guidance_can_only_be_attached_to_object_reports() {
        let guidance = OperationGuidance::no_safe_action("nothing to do")
            .build()
            .unwrap();
        let mut report = serde_json::json!([]);
        assert_eq!(
            attach_guidance(&mut report, guidance),
            Err(GuidanceError::ReportIsNotObject)
        );
    }

    #[test]
    fn shared_guidance_maps_async_results_to_exact_bounded_waits() {
        let mut report = serde_json::json!({
            "command": "run",
            "coordinator": "https://coordinator.example",
            "tenant": "tenant-a",
            "project": "project-a",
            "run_start": { "accepted": true, "process": "vp-123" }
        });
        ensure_report_guidance(&mut report).unwrap();

        assert_eq!(report["guidance"]["recommended"]["kind"], "wait");
        assert_eq!(
            report["guidance"]["recommended"]["command"],
            serde_json::json!([
                "clusterflux",
                "wait",
                "process",
                "--process",
                "vp-123",
                "--for",
                "terminal",
                "--timeout",
                "30m",
                "--coordinator",
                "https://coordinator.example",
                "--tenant",
                "tenant-a",
                "--project-id",
                "project-a"
            ])
        );
    }

    #[test]
    fn shared_guidance_keeps_confirmed_mutations_as_alternatives() {
        let mut report = serde_json::json!({
            "command": "process cancel",
            "confirmation_required": true,
            "target": {
                "coordinator": "https://coordinator.example",
                "tenant": "tenant-a",
                "project": "project-a",
                "process": "vp-123",
                "node": "node-a",
                "task": "task-a"
            },
            "machine_error": { "category": "policy" }
        });
        ensure_report_guidance(&mut report).unwrap();

        assert!(report["guidance"]["recommended"].is_null());
        assert_eq!(report["guidance"]["alternatives"][0]["mutating"], true);
        assert_eq!(
            report["guidance"]["alternatives"][0]["requires_confirmation"],
            true
        );
        assert_eq!(
            report["guidance"]["alternatives"][0]["command"],
            serde_json::json!([
                "clusterflux",
                "process",
                "cancel",
                "--process",
                "vp-123",
                "--node",
                "node-a",
                "--task",
                "task-a",
                "--coordinator",
                "https://coordinator.example",
                "--tenant",
                "tenant-a",
                "--project-id",
                "project-a",
                "--yes"
            ])
        );
    }

    #[test]
    fn wait_timeout_recommends_the_same_selector_without_retriggering() {
        let mut report = serde_json::json!({
            "command": "wait run",
            "status": "timeout",
            "selector": { "kind": "run", "run": "run-123" },
            "condition": "published",
            "timeout_ms": 900_000,
            "machine_error": { "category": "timeout" }
        });
        ensure_report_guidance(&mut report).unwrap();
        assert_eq!(
            report["guidance"]["recommended"]["command"],
            serde_json::json!([
                "clusterflux",
                "wait",
                "run",
                "--run",
                "run-123",
                "--for",
                "published",
                "--timeout",
                "900000ms"
            ])
        );
    }

    #[test]
    fn clean_terminal_reports_explicitly_require_no_follow_up() {
        let mut report = serde_json::json!({"command": "key list", "records": []});
        ensure_report_guidance(&mut report).unwrap();
        assert_eq!(
            report["guidance"]["no_safe_action_reason"],
            "operation completed; no follow-up is required"
        );
    }

    #[test]
    fn submitted_artifact_transfer_recommends_supported_inspection_not_a_fake_wait() {
        let mut report = serde_json::json!({
            "command": "artifact export",
            "coordinator": "https://coordinator.example",
            "export_plan": {"status": "transfer_created", "process": "vp-123"}
        });
        ensure_report_guidance(&mut report).unwrap();
        assert_eq!(
            report["guidance"]["recommended"]["command"],
            serde_json::json!([
                "clusterflux",
                "artifact",
                "list",
                "--process",
                "vp-123",
                "--coordinator",
                "https://coordinator.example"
            ])
        );
    }

    #[test]
    fn missing_coordinator_recommends_a_safe_preflight() {
        let mut report = serde_json::json!({
            "command": "process list",
            "status": "requires_coordinator",
            "processes": []
        });
        ensure_report_guidance(&mut report).unwrap();
        assert_eq!(
            report["guidance"]["recommended"]["command"],
            serde_json::json!(["clusterflux", "doctor"])
        );
    }

    #[test]
    fn coordinator_legacy_actions_are_validated_deduplicated_and_never_trusted_as_prose() {
        let mut report = serde_json::json!({
            "command": "error",
            "machine_error": {
                "category": "authentication",
                "coordinator_next_actions": [
                    "clusterflux login --browser",
                    "clusterflux auth status",
                    "ask an administrator for help",
                    "clusterflux node attach --enrollment-grant secret"
                ]
            }
        });
        ensure_report_guidance(&mut report).unwrap();
        assert_eq!(
            report["guidance"]["alternatives"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            report["guidance"]["alternatives"][0]["command"],
            serde_json::json!(["clusterflux", "auth", "status"])
        );
    }
}
