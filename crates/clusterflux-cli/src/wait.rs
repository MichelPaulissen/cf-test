use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use clusterflux_client::{ControlTransportError, ProtocolSession};
use clusterflux_core::{
    validate_commit_sha, ApiError, ApiErrorCategory, ApiErrorCode, AutomatedRunRecord,
    AutomatedRunState, NodeId, ProcessId, RepositoryId, RunId,
};
use clusterflux_protocol::{
    AuthenticatedCoordinatorRequest, CoordinatorRequest, CoordinatorResponse, NodeSummary,
    ProcessFinalResult, ProcessSummary,
};
use serde_json::{json, Value};

use crate::client::{is_loopback_coordinator, stored_session_for_coordinator};
use crate::config::read_cli_session;
use crate::process::hydrate_process_scope;
use crate::CliScopeArgs;

const NORMAL_POLL_INTERVAL: Duration = Duration::from_secs(2);
const INITIAL_TRANSIENT_BACKOFF: Duration = Duration::from_millis(250);
const MAX_TRANSIENT_BACKOFF: Duration = Duration::from_secs(5);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
const MAX_WAIT_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_WAIT_OBSERVATIONS: u64 = 50_000;
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_ERROR_MESSAGE_BYTES: usize = 2_048;

pub(crate) const WAIT_TIMEOUT_EXIT_CODE: i32 = 29;
pub(crate) const WAIT_TERMINAL_FAILURE_EXIT_CODE: i32 = 30;
pub(crate) const WAIT_INTERRUPTED_EXIT_CODE: i32 = 130;

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum WaitCommands {
    /// Wait for an automated run to appear, terminate, or publish.
    Run(WaitRunArgs),
    /// Wait for a virtual process to terminate.
    Process(WaitProcessArgs),
    /// Wait for a node identity to become ready or be removed.
    ///
    /// `gone` requires the identity to be absent; an offline worker is not gone.
    Node(WaitNodeArgs),
}

impl WaitCommands {
    pub(crate) fn json_output(&self) -> bool {
        match self {
            Self::Run(args) => args.scope.json,
            Self::Process(args) => args.scope.json,
            Self::Node(args) => args.scope.json,
        }
    }
}

#[derive(Clone, Debug, Args)]
#[group(id = "run_selector", required = true, multiple = false, args = ["run", "repository"])]
pub(crate) struct WaitRunArgs {
    /// Exact automated run identifier.
    #[arg(long, value_parser = parse_run_id)]
    run: Option<RunId>,
    /// Repository binding identifier, for example github:owner/repository.
    #[arg(long, value_parser = parse_repository_id, requires = "commit", conflicts_with = "run")]
    repository: Option<RepositoryId>,
    /// Exact lowercase 40-character Git commit SHA.
    #[arg(long, value_parser = parse_commit_sha, requires = "repository", conflicts_with = "run")]
    commit: Option<String>,
    #[arg(long = "for", value_enum)]
    condition: WaitRunCondition,
    /// Maximum time to wait, such as 30s, 5m, or 1h.
    #[arg(long, value_parser = parse_wait_duration)]
    timeout: Duration,
    /// Treat a failed or cancelled terminal run as a successful wait.
    #[arg(long)]
    accept_non_success: bool,
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct WaitProcessArgs {
    #[arg(long, value_parser = parse_process_id)]
    process: ProcessId,
    #[arg(long = "for", value_enum)]
    condition: WaitProcessCondition,
    /// Maximum time to wait, such as 30s, 5m, or 1h.
    #[arg(long, value_parser = parse_wait_duration)]
    timeout: Duration,
    /// Treat a failed or cancelled terminal process as a successful wait.
    #[arg(long)]
    accept_non_success: bool,
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct WaitNodeArgs {
    #[arg(long, value_parser = parse_node_id)]
    node: NodeId,
    #[arg(long = "for", value_enum)]
    condition: WaitNodeCondition,
    /// Maximum time to wait, such as 30s, 5m, or 1h.
    #[arg(long, value_parser = parse_wait_duration)]
    timeout: Duration,
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum WaitRunCondition {
    Appeared,
    Terminal,
    Published,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum WaitProcessCondition {
    Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum WaitNodeCondition {
    Ready,
    Gone,
}

pub(crate) fn wait_report(command: WaitCommands, cwd: &Path) -> Result<Value> {
    let (spec, scope, json_output) = WaitSpec::from_command(command);
    let mut backend = match CoordinatorWaitBackend::new(scope, cwd) {
        Ok(backend) => backend,
        Err(error) => {
            return Ok(final_report(
                &spec,
                &WaitSnapshot::absent(),
                Duration::ZERO,
                "error",
                None,
                Some(error.machine_error()),
            ));
        }
    };
    let clock = SystemWaitClock::new();
    let cancellation = install_ctrl_c_handler()?;
    let mut progress = StderrProgress {
        enabled: !json_output,
    };
    Ok(execute_wait(
        &spec,
        &mut backend,
        &clock,
        cancellation.as_ref(),
        &mut progress,
    ))
}

#[derive(Clone, Debug)]
struct WaitSpec {
    selector: WaitSelector,
    condition: WaitCondition,
    timeout: Duration,
    accept_non_success: bool,
}

impl WaitSpec {
    fn from_command(command: WaitCommands) -> (Self, CliScopeArgs, bool) {
        match command {
            WaitCommands::Run(args) => {
                let selector = match (args.run, args.repository, args.commit) {
                    (Some(run), None, None) => WaitSelector::RunId(run),
                    (None, Some(repository), Some(commit)) => {
                        WaitSelector::RepositoryCommit { repository, commit }
                    }
                    _ => unreachable!("clap enforces the run selector group"),
                };
                let condition = match args.condition {
                    WaitRunCondition::Appeared => WaitCondition::Appeared,
                    WaitRunCondition::Terminal => WaitCondition::Terminal,
                    WaitRunCondition::Published => WaitCondition::Published,
                };
                let json_output = args.scope.json;
                (
                    Self {
                        selector,
                        condition,
                        timeout: args.timeout,
                        accept_non_success: args.accept_non_success,
                    },
                    args.scope,
                    json_output,
                )
            }
            WaitCommands::Process(args) => {
                let json_output = args.scope.json;
                (
                    Self {
                        selector: WaitSelector::Process(args.process),
                        condition: match args.condition {
                            WaitProcessCondition::Terminal => WaitCondition::Terminal,
                        },
                        timeout: args.timeout,
                        accept_non_success: args.accept_non_success,
                    },
                    args.scope,
                    json_output,
                )
            }
            WaitCommands::Node(args) => {
                let json_output = args.scope.json;
                (
                    Self {
                        selector: WaitSelector::Node(args.node),
                        condition: match args.condition {
                            WaitNodeCondition::Ready => WaitCondition::Ready,
                            WaitNodeCondition::Gone => WaitCondition::Gone,
                        },
                        timeout: args.timeout,
                        accept_non_success: false,
                    },
                    args.scope,
                    json_output,
                )
            }
        }
    }

    fn command_name(&self) -> &'static str {
        match self.selector {
            WaitSelector::RunId(_) | WaitSelector::RepositoryCommit { .. } => "wait run",
            WaitSelector::Process(_) => "wait process",
            WaitSelector::Node(_) => "wait node",
        }
    }
}

#[derive(Clone, Debug)]
enum WaitSelector {
    RunId(RunId),
    RepositoryCommit {
        repository: RepositoryId,
        commit: String,
    },
    Process(ProcessId),
    Node(NodeId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaitCondition {
    Appeared,
    Terminal,
    Published,
    Ready,
    Gone,
}

impl WaitCondition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Appeared => "appeared",
            Self::Terminal => "terminal",
            Self::Published => "published",
            Self::Ready => "ready",
            Self::Gone => "gone",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalResult {
    Completed,
    Failed,
    Cancelled,
}

impl TerminalResult {
    fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    fn successful(self) -> bool {
        self == Self::Completed
    }
}

#[derive(Clone, Debug, Default)]
struct WaitSnapshot {
    resolved_ids: Vec<String>,
    run: Option<String>,
    process: Option<String>,
    node: Option<String>,
    state: Option<String>,
    terminal_result: Option<TerminalResult>,
    publication_url: Option<String>,
    node_online: Option<bool>,
}

impl WaitSnapshot {
    fn absent() -> Self {
        Self {
            state: Some("absent".to_owned()),
            ..Self::default()
        }
    }

    fn observed(&self) -> bool {
        !self.resolved_ids.is_empty()
    }

    fn progress_state(&self) -> String {
        if self.resolved_ids.len() > 1 {
            return format!("ambiguous ({})", self.resolved_ids.join(", "));
        }
        if !self.observed() {
            return "absent".to_owned();
        }
        if self.publication_url.is_some() {
            return "published".to_owned();
        }
        self.state.clone().unwrap_or_else(|| "observed".to_owned())
    }
}

trait WaitBackend {
    fn observe(
        &mut self,
        selector: &WaitSelector,
        remaining: Duration,
    ) -> std::result::Result<WaitSnapshot, WaitError>;
}

trait WaitClock {
    fn now(&self) -> Duration;
    fn sleep(&self, duration: Duration);
}

trait CancellationProbe {
    fn cancelled(&self) -> bool;
}

trait ProgressSink {
    fn state_changed(&mut self, state: &str);
}

struct SystemWaitClock {
    origin: Instant,
}

impl SystemWaitClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl WaitClock for SystemWaitClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

impl CancellationProbe for AtomicBool {
    fn cancelled(&self) -> bool {
        self.load(Ordering::Relaxed)
    }
}

struct StderrProgress {
    enabled: bool,
}

impl ProgressSink for StderrProgress {
    fn state_changed(&mut self, state: &str) {
        if self.enabled {
            eprintln!("wait state: {state}");
        }
    }
}

fn execute_wait(
    spec: &WaitSpec,
    backend: &mut dyn WaitBackend,
    clock: &dyn WaitClock,
    cancellation: &dyn CancellationProbe,
    progress: &mut dyn ProgressSink,
) -> Value {
    let started = clock.now();
    let deadline = started.saturating_add(spec.timeout);
    let mut snapshot = WaitSnapshot::absent();
    let mut ever_observed = false;
    let mut last_observed_snapshot = None;
    let mut last_progress_state = None;
    let mut last_bounded_error = None;
    let mut transient_backoff = INITIAL_TRANSIENT_BACKOFF;
    let mut observations = 0_u64;

    loop {
        if cancellation.cancelled() {
            let elapsed = clock.now().saturating_sub(started);
            let report_snapshot = report_snapshot(&snapshot, last_observed_snapshot.as_ref());
            return final_report(
                spec,
                &report_snapshot,
                elapsed,
                "interrupted",
                last_bounded_error,
                Some(machine_error(
                    "interrupted",
                    WAIT_INTERRUPTED_EXIT_CODE,
                    "wait interrupted by Ctrl-C",
                    true,
                )),
            );
        }

        let before_query = clock.now();
        if before_query >= deadline {
            let elapsed = before_query.saturating_sub(started);
            let report_snapshot = report_snapshot(&snapshot, last_observed_snapshot.as_ref());
            return final_report_with_observed(
                spec,
                &report_snapshot,
                ever_observed,
                elapsed,
                "timeout",
                last_bounded_error,
                Some(machine_error(
                    "timeout",
                    WAIT_TIMEOUT_EXIT_CODE,
                    "wait deadline expired before the requested condition was satisfied",
                    true,
                )),
            );
        }
        if observations >= MAX_WAIT_OBSERVATIONS {
            let elapsed = before_query.saturating_sub(started);
            let report_snapshot = report_snapshot(&snapshot, last_observed_snapshot.as_ref());
            return final_report_with_observed(
                spec,
                &report_snapshot,
                ever_observed,
                elapsed,
                "observation_limit",
                last_bounded_error,
                Some(machine_error(
                    "timeout",
                    WAIT_TIMEOUT_EXIT_CODE,
                    "wait observation limit reached before the requested condition was satisfied",
                    true,
                )),
            );
        }
        observations = observations.saturating_add(1);

        let delay = match backend.observe(&spec.selector, deadline.saturating_sub(before_query)) {
            Ok(observed) => {
                snapshot = observed;
                ever_observed |= snapshot.observed();
                if snapshot.observed() {
                    last_observed_snapshot = Some(snapshot.clone());
                }
                let progress_state = snapshot.progress_state();
                if last_progress_state.as_deref() != Some(progress_state.as_str()) {
                    progress.state_changed(&progress_state);
                    last_progress_state = Some(progress_state);
                }
                transient_backoff = INITIAL_TRANSIENT_BACKOFF;

                if snapshot.resolved_ids.len() > 1 {
                    let elapsed = clock.now().saturating_sub(started);
                    let report_snapshot =
                        report_snapshot(&snapshot, last_observed_snapshot.as_ref());
                    return final_report_with_observed(
                        spec,
                        &report_snapshot,
                        ever_observed,
                        elapsed,
                        "error",
                        last_bounded_error,
                        Some(machine_error(
                            "validation",
                            2,
                            "wait selector resolved to more than one target; use an exact identifier",
                            false,
                        )),
                    );
                }

                match evaluate(spec, &snapshot) {
                    WaitEvaluation::Pending => NORMAL_POLL_INTERVAL,
                    WaitEvaluation::Satisfied => {
                        let elapsed = clock.now().saturating_sub(started);
                        let report_snapshot =
                            report_snapshot(&snapshot, last_observed_snapshot.as_ref());
                        return final_report_with_observed(
                            spec,
                            &report_snapshot,
                            ever_observed,
                            elapsed,
                            "satisfied",
                            last_bounded_error,
                            None,
                        );
                    }
                    WaitEvaluation::NonSuccess(result) => {
                        let elapsed = clock.now().saturating_sub(started);
                        let report_snapshot =
                            report_snapshot(&snapshot, last_observed_snapshot.as_ref());
                        return final_report_with_observed(
                            spec,
                            &report_snapshot,
                            ever_observed,
                            elapsed,
                            "terminal_failure",
                            last_bounded_error,
                            Some(machine_error(
                                "program",
                                WAIT_TERMINAL_FAILURE_EXIT_CODE,
                                &format!(
                                    "target reached non-success terminal state {}",
                                    result.as_str()
                                ),
                                true,
                            )),
                        );
                    }
                }
            }
            Err(error) if error.transient => {
                last_bounded_error = Some(error.bounded_json());
                let requested = error
                    .retry_after
                    .unwrap_or_else(|| jittered_retry_delay(transient_backoff, observations));
                transient_backoff = double_duration(transient_backoff).min(MAX_TRANSIENT_BACKOFF);
                requested.min(MAX_RETRY_DELAY)
            }
            Err(error) => {
                let elapsed = clock.now().saturating_sub(started);
                let machine_error = error.machine_error();
                last_bounded_error = Some(error.bounded_json());
                let report_snapshot = report_snapshot(&snapshot, last_observed_snapshot.as_ref());
                return final_report_with_observed(
                    spec,
                    &report_snapshot,
                    ever_observed,
                    elapsed,
                    "error",
                    last_bounded_error,
                    Some(machine_error),
                );
            }
        };

        let now = clock.now();
        if now >= deadline {
            let elapsed = now.saturating_sub(started);
            let report_snapshot = report_snapshot(&snapshot, last_observed_snapshot.as_ref());
            return final_report_with_observed(
                spec,
                &report_snapshot,
                ever_observed,
                elapsed,
                "timeout",
                last_bounded_error,
                Some(machine_error(
                    "timeout",
                    WAIT_TIMEOUT_EXIT_CODE,
                    "wait deadline expired before the requested condition was satisfied",
                    true,
                )),
            );
        }
        sleep_with_cancellation(clock, cancellation, delay.min(deadline.saturating_sub(now)));
    }
}

fn report_snapshot(current: &WaitSnapshot, last_observed: Option<&WaitSnapshot>) -> WaitSnapshot {
    if current.observed() {
        return current.clone();
    }
    let Some(last_observed) = last_observed else {
        return current.clone();
    };
    WaitSnapshot {
        resolved_ids: last_observed.resolved_ids.clone(),
        run: last_observed.run.clone(),
        process: last_observed.process.clone(),
        node: last_observed.node.clone(),
        state: Some("absent".to_owned()),
        terminal_result: None,
        publication_url: None,
        node_online: Some(false),
    }
}

fn sleep_with_cancellation(
    clock: &dyn WaitClock,
    cancellation: &dyn CancellationProbe,
    duration: Duration,
) {
    let deadline = clock.now().saturating_add(duration);
    while !cancellation.cancelled() {
        let now = clock.now();
        if now >= deadline {
            break;
        }
        clock.sleep(deadline.saturating_sub(now).min(CANCELLATION_POLL_INTERVAL));
    }
}

enum WaitEvaluation {
    Pending,
    Satisfied,
    NonSuccess(TerminalResult),
}

fn evaluate(spec: &WaitSpec, snapshot: &WaitSnapshot) -> WaitEvaluation {
    match spec.condition {
        WaitCondition::Appeared => {
            if snapshot.observed() {
                WaitEvaluation::Satisfied
            } else {
                WaitEvaluation::Pending
            }
        }
        WaitCondition::Terminal => match snapshot.terminal_result {
            Some(result) if result.successful() || spec.accept_non_success => {
                WaitEvaluation::Satisfied
            }
            Some(result) => WaitEvaluation::NonSuccess(result),
            None => WaitEvaluation::Pending,
        },
        WaitCondition::Published => {
            if snapshot.publication_url.is_some() {
                WaitEvaluation::Satisfied
            } else {
                match snapshot.terminal_result {
                    Some(TerminalResult::Failed | TerminalResult::Cancelled)
                        if spec.accept_non_success =>
                    {
                        WaitEvaluation::Satisfied
                    }
                    Some(TerminalResult::Failed | TerminalResult::Cancelled)
                        if !spec.accept_non_success =>
                    {
                        WaitEvaluation::NonSuccess(
                            snapshot
                                .terminal_result
                                .expect("terminal result was matched"),
                        )
                    }
                    _ => WaitEvaluation::Pending,
                }
            }
        }
        WaitCondition::Ready => {
            if snapshot.observed() && snapshot.node_online == Some(true) {
                WaitEvaluation::Satisfied
            } else {
                WaitEvaluation::Pending
            }
        }
        WaitCondition::Gone => {
            if snapshot.observed() {
                WaitEvaluation::Pending
            } else {
                WaitEvaluation::Satisfied
            }
        }
    }
}

fn final_report(
    spec: &WaitSpec,
    snapshot: &WaitSnapshot,
    elapsed: Duration,
    status: &str,
    last_bounded_error: Option<Value>,
    machine_error: Option<Value>,
) -> Value {
    final_report_with_observed(
        spec,
        snapshot,
        snapshot.observed(),
        elapsed,
        status,
        last_bounded_error,
        machine_error,
    )
}

#[allow(clippy::too_many_arguments)]
fn final_report_with_observed(
    spec: &WaitSpec,
    snapshot: &WaitSnapshot,
    ever_observed: bool,
    elapsed: Duration,
    status: &str,
    last_bounded_error: Option<Value>,
    machine_error: Option<Value>,
) -> Value {
    json!({
        "command": spec.command_name(),
        "status": status,
        "selector": selector_json(&spec.selector),
        "condition": spec.condition.as_str(),
        "observed": ever_observed,
        "resolved_ids": snapshot.resolved_ids,
        "run": snapshot.run,
        "process": snapshot.process,
        "node": snapshot.node,
        "final_state": snapshot.state,
        "final_result": snapshot.terminal_result.map(TerminalResult::as_str),
        "publication_url": snapshot.publication_url,
        "elapsed_ms": duration_millis(elapsed),
        "timeout_ms": duration_millis(spec.timeout),
        "last_bounded_error": last_bounded_error,
        "machine_error": machine_error,
    })
}

fn selector_json(selector: &WaitSelector) -> Value {
    match selector {
        WaitSelector::RunId(run) => json!({ "kind": "run", "run": run }),
        WaitSelector::RepositoryCommit { repository, commit } => json!({
            "kind": "repository_commit",
            "repository": repository,
            "commit": commit,
        }),
        WaitSelector::Process(process) => json!({ "kind": "process", "process": process }),
        WaitSelector::Node(node) => json!({ "kind": "node", "node": node }),
    }
}

fn machine_error(
    category: &str,
    stable_exit_code: i32,
    message: &str,
    retryable_after_user_action: bool,
) -> Value {
    json!({
        "category": category,
        "stable_exit_code": stable_exit_code,
        "process_exit_code_applied": false,
        "retryable_after_user_action": retryable_after_user_action,
        "message": bounded_message(message),
        "safe_failure": true,
        "next_actions": [],
    })
}

#[derive(Clone, Debug)]
struct WaitError {
    kind: &'static str,
    message: String,
    transient: bool,
    status_code: Option<u16>,
    retry_after: Option<Duration>,
    api_code: Option<ApiErrorCode>,
    api_category: Option<ApiErrorCategory>,
}

impl WaitError {
    fn local(category: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind: category,
            message: bounded_message(&message.into()),
            transient: false,
            status_code: None,
            retry_after: None,
            api_code: None,
            api_category: None,
        }
    }

    fn api(error: ApiError) -> Self {
        Self {
            kind: "api",
            message: bounded_message(&error.message),
            transient: false,
            status_code: None,
            retry_after: None,
            api_code: Some(error.code),
            api_category: Some(error.category),
        }
    }

    fn transport(error: ControlTransportError) -> Self {
        let status_code = error.status_code();
        let retry_after = error.retry_after();
        let transient = match &error {
            ControlTransportError::Io(error) => matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::AddrNotAvailable
            ),
            ControlTransportError::Http(_) | ControlTransportError::Closed => true,
            ControlTransportError::HttpStatus { status, .. } => {
                matches!(status, 429 | 502 | 503 | 504)
            }
            _ => false,
        };
        Self {
            kind: "transport",
            message: bounded_message(&error.to_string()),
            transient,
            status_code,
            retry_after,
            api_code: None,
            api_category: None,
        }
    }

    fn is_not_found(&self) -> bool {
        self.api_code == Some(ApiErrorCode::NotFound)
    }

    fn bounded_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "message": self.message,
            "transient": self.transient,
            "status_code": self.status_code,
            "retry_after_ms": self.retry_after.map(duration_millis),
            "api_code": self.api_code,
            "api_category": self.api_category,
        })
    }

    fn machine_error(&self) -> Value {
        let (category, exit_code, retryable) = match self.api_code {
            Some(ApiErrorCode::Unauthenticated | ApiErrorCode::SessionExpired) => {
                ("authentication", 20, true)
            }
            Some(ApiErrorCode::AccountSuspended | ApiErrorCode::Forbidden) => {
                ("authorization", 21, true)
            }
            Some(ApiErrorCode::QuotaExceeded | ApiErrorCode::ArtifactLimitExceeded) => {
                ("quota", 22, true)
            }
            Some(ApiErrorCode::NoCapableNode) => ("capability", 24, true),
            Some(
                ApiErrorCode::NodeOffline
                | ApiErrorCode::ArtifactUnavailable
                | ApiErrorCode::TemporaryCapacity,
            ) => ("connectivity", 25, true),
            Some(ApiErrorCode::ValidationError) => ("validation", 2, false),
            Some(ApiErrorCode::NotFound | ApiErrorCode::Conflict) => ("state", 2, false),
            Some(ApiErrorCode::ActiveProcessExists) => ("active_process", 28, true),
            Some(ApiErrorCode::TaskNotRestartable | ApiErrorCode::DebugEpochPartial) => {
                ("state", 2, true)
            }
            Some(ApiErrorCode::InternalError) => ("internal", 1, true),
            None if self.kind == "authentication" => ("authentication", 20, true),
            None if self.kind == "transport" => ("connectivity", 25, true),
            None => (self.kind, 1, false),
        };
        machine_error(category, exit_code, &self.message, retryable)
    }
}

struct CoordinatorWaitBackend {
    coordinator: String,
    tenant: String,
    project: String,
    user: String,
    session_secret: Option<String>,
    request_sequence: u64,
}

impl CoordinatorWaitBackend {
    fn new(mut scope: CliScopeArgs, cwd: &Path) -> std::result::Result<Self, WaitError> {
        let stored = read_cli_session(cwd)
            .map_err(|error| WaitError::local("configuration", error.to_string()))?;
        hydrate_process_scope(&mut scope, stored.as_ref());
        let coordinator = scope
            .coordinator
            .clone()
            .ok_or_else(|| WaitError::local("authentication", "no coordinator is configured"))?;
        let session_secret = stored_session_for_coordinator(&coordinator, stored.as_ref())
            .and_then(|session| session.session_secret.clone());
        Ok(Self {
            coordinator,
            tenant: scope.tenant,
            project: scope.project,
            user: scope.user,
            session_secret,
            request_sequence: 0,
        })
    }

    fn session(&mut self, remaining: Duration) -> std::result::Result<ProtocolSession, WaitError> {
        self.request_sequence = self.request_sequence.saturating_add(1);
        let (connect_timeout, io_timeout) = bounded_transport_timeouts(remaining);
        ProtocolSession::connect_with_timeouts(
            &self.coordinator,
            format!("cli-wait-{}", self.request_sequence),
            connect_timeout,
            io_timeout,
        )
        .map_err(WaitError::transport)
    }

    fn authenticated_request(
        &self,
        request: AuthenticatedCoordinatorRequest,
    ) -> std::result::Result<CoordinatorRequest, WaitError> {
        let session_secret = self.session_secret.clone().ok_or_else(|| {
            WaitError::local(
                "authentication",
                format!(
                    "no authenticated CLI session matches coordinator {}; run `clusterflux login --browser` from the current project",
                    self.coordinator
                ),
            )
        })?;
        Ok(CoordinatorRequest::Authenticated {
            session_secret,
            request,
        })
    }

    fn authenticated_or_local(
        &self,
        authenticated: AuthenticatedCoordinatorRequest,
        local: CoordinatorRequest,
    ) -> std::result::Result<CoordinatorRequest, WaitError> {
        if self.session_secret.is_some() {
            self.authenticated_request(authenticated)
        } else if is_loopback_coordinator(&self.coordinator) {
            Ok(local)
        } else {
            self.authenticated_request(authenticated)
        }
    }

    fn request(
        session: &mut ProtocolSession,
        request: CoordinatorRequest,
    ) -> std::result::Result<CoordinatorResponse, WaitError> {
        match session
            .request_allow_error(&request)
            .map_err(WaitError::transport)?
        {
            CoordinatorResponse::Error { error } => Err(WaitError::api(error)),
            response => Ok(response),
        }
    }

    fn observe_run_id(
        &mut self,
        run: &RunId,
        remaining: Duration,
    ) -> std::result::Result<WaitSnapshot, WaitError> {
        let request =
            self.authenticated_request(AuthenticatedCoordinatorRequest::GetAutomatedRun {
                run: run.to_string(),
            })?;
        let mut session = self.session(remaining)?;
        match Self::request(&mut session, request) {
            Ok(CoordinatorResponse::AutomatedRun { run, .. }) => Ok(run_snapshot(&run)),
            Ok(response) => Err(unexpected_response("automated_run", &response)),
            Err(error) if error.is_not_found() => Ok(WaitSnapshot::absent()),
            Err(error) => Err(error),
        }
    }

    fn observe_repository_commit(
        &mut self,
        repository: &RepositoryId,
        commit: &str,
        remaining: Duration,
    ) -> std::result::Result<WaitSnapshot, WaitError> {
        if self.session_secret.is_none() {
            return Err(WaitError::local(
                "authentication",
                format!(
                    "no authenticated CLI session matches coordinator {}; run `clusterflux login --browser` from the current project",
                    self.coordinator
                ),
            ));
        }
        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        let mut matches = Vec::new();
        let mut session = self.session(remaining)?;
        loop {
            let request =
                self.authenticated_request(AuthenticatedCoordinatorRequest::ListAutomatedRuns {
                    cursor: cursor.clone(),
                    limit: 64,
                })?;
            let response = Self::request(&mut session, request)?;
            let CoordinatorResponse::AutomatedRuns {
                runs, next_cursor, ..
            } = response
            else {
                return Err(unexpected_response("automated_runs", &response));
            };
            matches.extend(runs.into_iter().filter(|run| {
                &run.repository_id == repository && run.commit_sha.as_str() == commit
            }));
            let Some(next) = next_cursor else {
                break;
            };
            if !seen_cursors.insert(next.clone()) {
                return Err(WaitError::local(
                    "protocol",
                    "coordinator repeated an automated-run page cursor",
                ));
            }
            cursor = Some(next);
        }
        Ok(matched_run_snapshot(matches))
    }

    fn observe_process(
        &mut self,
        requested: &ProcessId,
        remaining: Duration,
    ) -> std::result::Result<WaitSnapshot, WaitError> {
        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        let mut session = self.session(remaining)?;
        loop {
            let authenticated = AuthenticatedCoordinatorRequest::ListProcessSummaries {
                cursor: cursor.clone(),
                limit: 100,
            };
            let local = CoordinatorRequest::ListProcessSummaries {
                tenant: self.tenant.clone(),
                project: self.project.clone(),
                actor_user: self.user.clone(),
                cursor: cursor.clone(),
                limit: 100,
            };
            let request = self.authenticated_or_local(authenticated, local)?;
            let response = Self::request(&mut session, request)?;
            let CoordinatorResponse::ProcessSummaries {
                processes,
                next_cursor,
                ..
            } = response
            else {
                return Err(unexpected_response("process_summaries", &response));
            };
            if let Some(process) = processes
                .iter()
                .find(|process| &process.process == requested)
            {
                return Ok(process_snapshot(process));
            }
            let Some(next) = next_cursor else {
                return Ok(WaitSnapshot::absent());
            };
            if !seen_cursors.insert(next.clone()) {
                return Err(WaitError::local(
                    "protocol",
                    "coordinator repeated a process-summary page cursor",
                ));
            }
            cursor = Some(next);
        }
    }

    fn observe_node(
        &mut self,
        requested: &NodeId,
        remaining: Duration,
    ) -> std::result::Result<WaitSnapshot, WaitError> {
        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        let mut session = self.session(remaining)?;
        loop {
            let authenticated = AuthenticatedCoordinatorRequest::ListNodeSummaries {
                cursor: cursor.clone(),
                limit: 100,
            };
            let local = CoordinatorRequest::ListNodeSummaries {
                tenant: self.tenant.clone(),
                project: self.project.clone(),
                actor_user: self.user.clone(),
                cursor: cursor.clone(),
                limit: 100,
            };
            let request = self.authenticated_or_local(authenticated, local)?;
            let response = Self::request(&mut session, request)?;
            let CoordinatorResponse::NodeSummaries {
                nodes, next_cursor, ..
            } = response
            else {
                return Err(unexpected_response("node_summaries", &response));
            };
            if let Some(node) = nodes.iter().find(|node| &node.id == requested) {
                return Ok(node_snapshot(node));
            }
            let Some(next) = next_cursor else {
                return Ok(WaitSnapshot::absent());
            };
            if !seen_cursors.insert(next.clone()) {
                return Err(WaitError::local(
                    "protocol",
                    "coordinator repeated a node-summary page cursor",
                ));
            }
            cursor = Some(next);
        }
    }
}

impl WaitBackend for CoordinatorWaitBackend {
    fn observe(
        &mut self,
        selector: &WaitSelector,
        remaining: Duration,
    ) -> std::result::Result<WaitSnapshot, WaitError> {
        match selector {
            WaitSelector::RunId(run) => self.observe_run_id(run, remaining),
            WaitSelector::RepositoryCommit { repository, commit } => {
                self.observe_repository_commit(repository, commit, remaining)
            }
            WaitSelector::Process(process) => self.observe_process(process, remaining),
            WaitSelector::Node(node) => self.observe_node(node, remaining),
        }
    }
}

fn bounded_transport_timeouts(remaining: Duration) -> (Duration, Duration) {
    let minimum = Duration::from_millis(1);
    let half = (remaining / 2).max(minimum);
    let connect_timeout = half.min(Duration::from_secs(10));
    let io_timeout = remaining
        .saturating_sub(connect_timeout)
        .max(minimum)
        .min(Duration::from_secs(30));
    (connect_timeout, io_timeout)
}

fn run_snapshot(run: &AutomatedRunRecord) -> WaitSnapshot {
    WaitSnapshot {
        resolved_ids: vec![run.run_id.to_string()],
        run: Some(run.run_id.to_string()),
        process: run.process_id.as_ref().map(ToString::to_string),
        node: None,
        state: Some(run_state_name(&run.state).to_owned()),
        terminal_result: run_terminal_result(&run.state),
        publication_url: run.publication_url.clone(),
        node_online: None,
    }
}

fn matched_run_snapshot(runs: Vec<AutomatedRunRecord>) -> WaitSnapshot {
    if runs.is_empty() {
        return WaitSnapshot::absent();
    }
    if runs.len() == 1 {
        return run_snapshot(&runs[0]);
    }
    WaitSnapshot {
        resolved_ids: runs.iter().map(|run| run.run_id.to_string()).collect(),
        ..WaitSnapshot::default()
    }
}

fn process_snapshot(process: &ProcessSummary) -> WaitSnapshot {
    WaitSnapshot {
        resolved_ids: vec![process.process.to_string()],
        run: None,
        process: Some(process.process.to_string()),
        node: None,
        state: Some(process_activity_name(&process.activity).to_owned()),
        terminal_result: process.final_result.as_ref().map(|result| match result {
            ProcessFinalResult::Completed => TerminalResult::Completed,
            ProcessFinalResult::Failed => TerminalResult::Failed,
            ProcessFinalResult::Cancelled => TerminalResult::Cancelled,
        }),
        publication_url: None,
        node_online: None,
    }
}

fn node_snapshot(node: &NodeSummary) -> WaitSnapshot {
    WaitSnapshot {
        resolved_ids: vec![node.id.to_string()],
        run: None,
        process: None,
        node: Some(node.id.to_string()),
        state: Some(node.runtime_state.clone()),
        terminal_result: None,
        publication_url: None,
        node_online: Some(node.online),
    }
}

fn run_state_name(state: &AutomatedRunState) -> &'static str {
    match state {
        AutomatedRunState::Accepted => "accepted",
        AutomatedRunState::LoadingSource => "loading_source",
        AutomatedRunState::WaitingForCompilerNode => "waiting_for_compiler_node",
        AutomatedRunState::CompilingWorkflow => "compiling_workflow",
        AutomatedRunState::WaitingForProcessSlot => "waiting_for_process_slot",
        AutomatedRunState::Launching => "launching",
        AutomatedRunState::Running => "running",
        AutomatedRunState::Completed => "completed",
        AutomatedRunState::Failed => "failed",
        AutomatedRunState::Cancelled => "cancelled",
    }
}

fn run_terminal_result(state: &AutomatedRunState) -> Option<TerminalResult> {
    match state {
        AutomatedRunState::Completed => Some(TerminalResult::Completed),
        AutomatedRunState::Failed => Some(TerminalResult::Failed),
        AutomatedRunState::Cancelled => Some(TerminalResult::Cancelled),
        _ => None,
    }
}

fn process_activity_name(state: &clusterflux_protocol::ProcessActivityState) -> &'static str {
    use clusterflux_protocol::ProcessActivityState;
    match state {
        ProcessActivityState::Running => "running",
        ProcessActivityState::WaitingForNode => "waiting_for_node",
        ProcessActivityState::WaitingForTask => "waiting_for_task",
        ProcessActivityState::AwaitingAction => "awaiting_action",
        ProcessActivityState::DebugEpochPartial => "debug_epoch_partial",
        ProcessActivityState::Cancelling => "cancelling",
        ProcessActivityState::Completed => "completed",
        ProcessActivityState::Failed => "failed",
        ProcessActivityState::Cancelled => "cancelled",
    }
}

fn unexpected_response(expected: &str, response: &CoordinatorResponse) -> WaitError {
    WaitError::local(
        "protocol",
        format!(
            "coordinator returned {}, expected {expected}",
            response.kind()
        ),
    )
}

fn install_ctrl_c_handler() -> Result<Arc<AtomicBool>> {
    static INTERRUPTED: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    if let Some(interrupted) = INTERRUPTED.get() {
        interrupted.store(false, Ordering::Relaxed);
        return Ok(Arc::clone(interrupted));
    }
    let interrupted = Arc::new(AtomicBool::new(false));
    let handler_flag = Arc::clone(&interrupted);
    ctrlc::set_handler(move || handler_flag.store(true, Ordering::Relaxed))
        .context("install Ctrl-C handler for bounded wait")?;
    let _ = INTERRUPTED.set(Arc::clone(&interrupted));
    Ok(interrupted)
}

fn parse_run_id(value: &str) -> std::result::Result<RunId, String> {
    RunId::try_new(value).map_err(|error| error.to_string())
}

fn parse_process_id(value: &str) -> std::result::Result<ProcessId, String> {
    ProcessId::try_new(value).map_err(|error| error.to_string())
}

fn parse_node_id(value: &str) -> std::result::Result<NodeId, String> {
    NodeId::try_new(value).map_err(|error| error.to_string())
}

fn parse_repository_id(value: &str) -> std::result::Result<RepositoryId, String> {
    RepositoryId::try_new(value).map_err(|error| error.to_string())
}

fn parse_commit_sha(value: &str) -> std::result::Result<String, String> {
    validate_commit_sha(value)?;
    Ok(value.to_owned())
}

pub(crate) fn parse_wait_duration(value: &str) -> std::result::Result<Duration, String> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let (amount, unit) = value.split_at(split);
    if amount.is_empty() || unit.is_empty() || unit.len() > 2 {
        return Err("duration must be a positive integer followed by ms, s, m, or h".to_owned());
    }
    let amount = amount
        .parse::<u64>()
        .map_err(|_| "duration amount is invalid or too large".to_owned())?;
    if amount == 0 {
        return Err("duration must be greater than zero".to_owned());
    }
    let duration = match unit {
        "ms" => Duration::from_millis(amount),
        "s" => Duration::from_secs(amount),
        "m" => Duration::from_secs(
            amount
                .checked_mul(60)
                .ok_or_else(|| "duration is too large".to_owned())?,
        ),
        "h" => Duration::from_secs(
            amount
                .checked_mul(60 * 60)
                .ok_or_else(|| "duration is too large".to_owned())?,
        ),
        _ => return Err("duration unit must be ms, s, m, or h".to_owned()),
    };
    if duration > MAX_WAIT_DURATION {
        return Err("duration must not exceed 24h".to_owned());
    }
    Ok(duration)
}

fn bounded_message(message: &str) -> String {
    if message.len() <= MAX_ERROR_MESSAGE_BYTES {
        return message.to_owned();
    }
    let mut end = MAX_ERROR_MESSAGE_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &message[..end])
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

fn double_duration(duration: Duration) -> Duration {
    duration.checked_mul(2).unwrap_or(Duration::MAX)
}

fn jittered_retry_delay(base: Duration, observation: u64) -> Duration {
    let entropy = observation
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .rotate_left(17);
    let permille = 750_u128 + u128::from(entropy % 501);
    let millis = base.as_millis().saturating_mul(permille) / 1_000;
    Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX)).min(MAX_TRANSIENT_BACKOFF)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;

    use clap::Parser;

    use super::*;
    use crate::{Cli, Commands};

    struct FakeClock {
        now: Cell<Duration>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                now: Cell::new(Duration::ZERO),
            }
        }
    }

    impl WaitClock for FakeClock {
        fn now(&self) -> Duration {
            self.now.get()
        }

        fn sleep(&self, duration: Duration) {
            self.now.set(self.now.get().saturating_add(duration));
        }
    }

    struct FakeCancellation {
        cancelled: Cell<bool>,
    }

    impl CancellationProbe for FakeCancellation {
        fn cancelled(&self) -> bool {
            self.cancelled.get()
        }
    }

    struct CancelAfterSleepClock<'a> {
        now: Cell<Duration>,
        cancellation: &'a Cell<bool>,
    }

    impl WaitClock for CancelAfterSleepClock<'_> {
        fn now(&self) -> Duration {
            self.now.get()
        }

        fn sleep(&self, duration: Duration) {
            self.now.set(self.now.get().saturating_add(duration));
            self.cancellation.set(true);
        }
    }

    struct FakeBackend {
        observations: VecDeque<std::result::Result<WaitSnapshot, WaitError>>,
        last: std::result::Result<WaitSnapshot, WaitError>,
    }

    impl FakeBackend {
        fn snapshots(snapshots: impl IntoIterator<Item = WaitSnapshot>) -> Self {
            let observations = snapshots.into_iter().map(Ok).collect::<VecDeque<_>>();
            Self {
                observations,
                last: Ok(WaitSnapshot::absent()),
            }
        }

        fn results(
            results: impl IntoIterator<Item = std::result::Result<WaitSnapshot, WaitError>>,
        ) -> Self {
            Self {
                observations: results.into_iter().collect(),
                last: Ok(WaitSnapshot::absent()),
            }
        }
    }

    impl WaitBackend for FakeBackend {
        fn observe(
            &mut self,
            _selector: &WaitSelector,
            _remaining: Duration,
        ) -> std::result::Result<WaitSnapshot, WaitError> {
            if let Some(next) = self.observations.pop_front() {
                self.last = next.clone();
            }
            self.last.clone()
        }
    }

    #[derive(Default)]
    struct RecordingProgress {
        states: Vec<String>,
    }

    impl ProgressSink for RecordingProgress {
        fn state_changed(&mut self, state: &str) {
            self.states.push(state.to_owned());
        }
    }

    fn run_spec(condition: WaitCondition, timeout: Duration) -> WaitSpec {
        WaitSpec {
            selector: WaitSelector::RunId(RunId::from("run-1")),
            condition,
            timeout,
            accept_non_success: false,
        }
    }

    fn run_snapshot_for(state: &str) -> WaitSnapshot {
        let terminal_result = match state {
            "completed" => Some(TerminalResult::Completed),
            "failed" => Some(TerminalResult::Failed),
            "cancelled" => Some(TerminalResult::Cancelled),
            _ => None,
        };
        WaitSnapshot {
            resolved_ids: vec!["run-1".to_owned()],
            run: Some("run-1".to_owned()),
            state: Some(state.to_owned()),
            terminal_result,
            ..WaitSnapshot::default()
        }
    }

    fn execute(spec: &WaitSpec, backend: &mut dyn WaitBackend) -> (Value, Vec<String>) {
        let clock = FakeClock::new();
        let cancellation = FakeCancellation {
            cancelled: Cell::new(false),
        };
        let mut progress = RecordingProgress::default();
        let report = execute_wait(spec, backend, &clock, &cancellation, &mut progress);
        (report, progress.states)
    }

    #[test]
    fn duration_parser_is_bounded_and_requires_a_unit() {
        assert_eq!(
            parse_wait_duration("250ms").unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(parse_wait_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_wait_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(
            parse_wait_duration("1h").unwrap(),
            Duration::from_secs(3600)
        );
        for invalid in [
            "",
            "0s",
            "30",
            "-1s",
            "1d",
            "25h",
            "1.5s",
            "999999999999999999999h",
        ] {
            assert!(parse_wait_duration(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn transient_retry_jitter_is_bounded() {
        for observation in 1..1_000 {
            let delay = jittered_retry_delay(Duration::from_secs(4), observation);
            assert!(delay >= Duration::from_secs(3));
            assert!(delay <= Duration::from_secs(5));
        }
    }

    #[test]
    fn documented_wait_command_surface_parses() {
        let commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        for args in [
            vec![
                "clusterflux",
                "wait",
                "run",
                "--run",
                "run-1",
                "--for",
                "terminal",
                "--timeout",
                "30m",
            ],
            vec![
                "clusterflux",
                "wait",
                "run",
                "--repository",
                "github:owner/repository",
                "--commit",
                commit,
                "--for",
                "appeared",
                "--timeout",
                "5m",
            ],
            vec![
                "clusterflux",
                "wait",
                "run",
                "--repository",
                "github:owner/repository",
                "--commit",
                commit,
                "--for",
                "published",
                "--timeout",
                "45m",
                "--accept-non-success",
                "--json",
            ],
            vec![
                "clusterflux",
                "wait",
                "process",
                "--process",
                "process-1",
                "--for",
                "terminal",
                "--timeout",
                "30m",
            ],
            vec![
                "clusterflux",
                "wait",
                "node",
                "--node",
                "node-1",
                "--for",
                "ready",
                "--timeout",
                "5m",
            ],
            vec![
                "clusterflux",
                "wait",
                "node",
                "--node",
                "node-1",
                "--for",
                "gone",
                "--timeout",
                "5m",
            ],
        ] {
            let parsed = Cli::try_parse_from(args).unwrap();
            assert!(matches!(parsed.command, Commands::Wait { .. }));
        }
    }

    #[test]
    fn wait_parser_rejects_unbounded_and_invalid_selectors() {
        let commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        for args in [
            vec![
                "clusterflux",
                "wait",
                "run",
                "--run",
                "run-1",
                "--for",
                "terminal",
            ],
            vec![
                "clusterflux",
                "wait",
                "run",
                "--repository",
                "github:owner/repository",
                "--for",
                "appeared",
                "--timeout",
                "5m",
            ],
            vec![
                "clusterflux",
                "wait",
                "run",
                "--run",
                "run-1",
                "--repository",
                "github:owner/repository",
                "--commit",
                commit,
                "--for",
                "appeared",
                "--timeout",
                "5m",
            ],
            vec![
                "clusterflux",
                "wait",
                "process",
                "--process",
                "process-1",
                "--for",
                "appeared",
                "--timeout",
                "5m",
            ],
            vec![
                "clusterflux",
                "wait",
                "node",
                "--node",
                "node-1",
                "--for",
                "terminal",
                "--timeout",
                "5m",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn absent_run_can_appear_late_and_then_complete() {
        let mut backend = FakeBackend::snapshots([
            WaitSnapshot::absent(),
            run_snapshot_for("running"),
            run_snapshot_for("running"),
            run_snapshot_for("completed"),
        ]);
        let (report, progress) = execute(
            &run_spec(WaitCondition::Terminal, Duration::from_secs(10)),
            &mut backend,
        );
        assert_eq!(report["status"], "satisfied");
        assert_eq!(report["observed"], true);
        assert_eq!(report["final_result"], "completed");
        assert_eq!(progress, vec!["absent", "running", "completed"]);
    }

    #[test]
    fn failed_and_cancelled_terminals_are_nonzero_unless_accepted() {
        for state in ["failed", "cancelled"] {
            let mut backend = FakeBackend::snapshots([run_snapshot_for(state)]);
            let (report, _) = execute(
                &run_spec(WaitCondition::Terminal, Duration::from_secs(5)),
                &mut backend,
            );
            assert_eq!(report["status"], "terminal_failure");
            assert_eq!(
                report["machine_error"]["stable_exit_code"],
                WAIT_TERMINAL_FAILURE_EXIT_CODE
            );

            let mut accepted = run_spec(WaitCondition::Terminal, Duration::from_secs(5));
            accepted.accept_non_success = true;
            let mut backend = FakeBackend::snapshots([run_snapshot_for(state)]);
            let (report, _) = execute(&accepted, &mut backend);
            assert_eq!(report["status"], "satisfied");
            assert!(report["machine_error"].is_null());
        }
    }

    #[test]
    fn completed_and_failed_processes_use_the_same_terminal_contract() {
        for (result, expected_status) in [
            (TerminalResult::Completed, "satisfied"),
            (TerminalResult::Failed, "terminal_failure"),
        ] {
            let spec = WaitSpec {
                selector: WaitSelector::Process(ProcessId::from("process-1")),
                condition: WaitCondition::Terminal,
                timeout: Duration::from_secs(5),
                accept_non_success: false,
            };
            let snapshot = WaitSnapshot {
                resolved_ids: vec!["process-1".to_owned()],
                process: Some("process-1".to_owned()),
                state: Some(result.as_str().to_owned()),
                terminal_result: Some(result),
                ..WaitSnapshot::default()
            };
            let mut backend = FakeBackend::snapshots([snapshot]);
            let (report, _) = execute(&spec, &mut backend);
            assert_eq!(report["status"], expected_status);
        }
    }

    #[test]
    fn completed_run_can_wait_for_late_publication_url() {
        let completed = run_snapshot_for("completed");
        let mut published = completed.clone();
        published.publication_url = Some("https://example.test/release/1".to_owned());
        let mut backend = FakeBackend::snapshots([completed, published]);
        let (report, progress) = execute(
            &run_spec(WaitCondition::Published, Duration::from_secs(5)),
            &mut backend,
        );
        assert_eq!(report["status"], "satisfied");
        assert_eq!(report["publication_url"], "https://example.test/release/1");
        assert_eq!(progress, vec!["completed", "published"]);
    }

    #[test]
    fn publication_wait_can_explicitly_accept_a_non_success_terminal() {
        let mut spec = run_spec(WaitCondition::Published, Duration::from_secs(5));
        spec.accept_non_success = true;
        let mut backend = FakeBackend::snapshots([run_snapshot_for("failed")]);
        let (report, _) = execute(&spec, &mut backend);
        assert_eq!(report["status"], "satisfied");
        assert_eq!(report["final_result"], "failed");
        assert!(report["publication_url"].is_null());
        assert!(report["machine_error"].is_null());
    }

    #[test]
    fn node_ready_and_gone_follow_identity_presence() {
        let node = WaitSnapshot {
            resolved_ids: vec!["node-1".to_owned()],
            node: Some("node-1".to_owned()),
            state: Some("offline".to_owned()),
            node_online: Some(false),
            ..WaitSnapshot::default()
        };
        let mut ready = node.clone();
        ready.state = Some("online".to_owned());
        ready.node_online = Some(true);
        let ready_spec = WaitSpec {
            selector: WaitSelector::Node(NodeId::from("node-1")),
            condition: WaitCondition::Ready,
            timeout: Duration::from_secs(5),
            accept_non_success: false,
        };
        let mut backend = FakeBackend::snapshots([WaitSnapshot::absent(), node.clone(), ready]);
        let (report, _) = execute(&ready_spec, &mut backend);
        assert_eq!(report["status"], "satisfied");

        let gone_spec = WaitSpec {
            condition: WaitCondition::Gone,
            ..ready_spec
        };
        let mut backend = FakeBackend::snapshots([node, WaitSnapshot::absent()]);
        let (report, _) = execute(&gone_spec, &mut backend);
        assert_eq!(report["status"], "satisfied");
        assert_eq!(report["observed"], true);
        assert_eq!(report["node"], "node-1");
        assert_eq!(report["final_state"], "absent");
    }

    #[test]
    fn transient_failures_retry_and_preserve_the_last_bounded_error() {
        let transient = WaitError {
            kind: "transport",
            message: "temporary gateway failure".to_owned(),
            transient: true,
            status_code: Some(503),
            retry_after: Some(Duration::from_millis(50)),
            api_code: None,
            api_category: None,
        };
        let mut backend = FakeBackend::results([Err(transient), Ok(run_snapshot_for("completed"))]);
        let (report, _) = execute(
            &run_spec(WaitCondition::Terminal, Duration::from_secs(5)),
            &mut backend,
        );
        assert_eq!(report["status"], "satisfied");
        assert_eq!(report["last_bounded_error"]["status_code"], 503);
        assert_eq!(report["elapsed_ms"], 50);
    }

    #[test]
    fn retry_policy_is_limited_to_transient_transport_and_selected_http_statuses() {
        for status in [429, 502, 503, 504] {
            let error = WaitError::transport(ControlTransportError::HttpStatus {
                status,
                status_text: "temporary".to_owned(),
                retry_after: Some(Duration::from_secs(45)),
            });
            assert!(error.transient);
            assert_eq!(error.retry_after, Some(Duration::from_secs(45)));
        }
        let error = WaitError::transport(ControlTransportError::HttpStatus {
            status: 500,
            status_text: "internal".to_owned(),
            retry_after: None,
        });
        assert!(!error.transient);
        assert!(!WaitError::transport(ControlTransportError::Protocol("bad".to_owned())).transient);
        assert!(
            !WaitError::transport(ControlTransportError::Json(
                serde_json::from_str::<Value>("{").unwrap_err()
            ))
            .transient
        );
    }

    #[test]
    fn authentication_and_protocol_errors_fail_immediately() {
        for error in [
            WaitError::api(ApiError::new(
                ApiErrorCode::SessionExpired,
                ApiErrorCategory::Authentication,
                "session expired",
                false,
                "request-1",
            )),
            WaitError::local("protocol", "malformed response"),
        ] {
            let mut backend = FakeBackend::results([Err(error)]);
            let (report, _) = execute(
                &run_spec(WaitCondition::Terminal, Duration::from_secs(5)),
                &mut backend,
            );
            assert_eq!(report["status"], "error");
            assert_eq!(report["elapsed_ms"], 0);
        }
    }

    #[test]
    fn ambiguous_selector_fails_with_all_resolved_ids() {
        let mut backend = FakeBackend::snapshots([WaitSnapshot {
            resolved_ids: vec!["run-1".to_owned(), "run-2".to_owned()],
            ..WaitSnapshot::default()
        }]);
        let (report, _) = execute(
            &run_spec(WaitCondition::Appeared, Duration::from_secs(5)),
            &mut backend,
        );
        assert_eq!(report["status"], "error");
        assert_eq!(report["observed"], true);
        assert_eq!(report["resolved_ids"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn timeout_before_appearance_has_a_distinct_exit_code() {
        let mut backend = FakeBackend::snapshots([WaitSnapshot::absent()]);
        let (report, _) = execute(
            &run_spec(WaitCondition::Appeared, Duration::from_secs(5)),
            &mut backend,
        );
        assert_eq!(report["status"], "timeout");
        assert_eq!(report["observed"], false);
        assert_eq!(report["elapsed_ms"], 5_000);
        assert_eq!(
            report["machine_error"]["stable_exit_code"],
            WAIT_TIMEOUT_EXIT_CODE
        );
    }

    #[test]
    fn timeout_after_observation_preserves_the_resolved_target() {
        let mut backend = FakeBackend::snapshots([run_snapshot_for("running")]);
        let (report, _) = execute(
            &run_spec(WaitCondition::Terminal, Duration::from_secs(3)),
            &mut backend,
        );
        assert_eq!(report["status"], "timeout");
        assert_eq!(report["observed"], true);
        assert_eq!(report["run"], "run-1");
        assert_eq!(report["final_state"], "running");
    }

    #[test]
    fn ctrl_c_returns_a_final_interrupted_record() {
        let cancelled = Cell::new(false);
        let clock = CancelAfterSleepClock {
            now: Cell::new(Duration::ZERO),
            cancellation: &cancelled,
        };
        struct BorrowedCancellation<'a>(&'a Cell<bool>);
        impl CancellationProbe for BorrowedCancellation<'_> {
            fn cancelled(&self) -> bool {
                self.0.get()
            }
        }
        let borrowed = BorrowedCancellation(&cancelled);
        let mut backend = FakeBackend::snapshots([WaitSnapshot::absent()]);
        let mut progress = RecordingProgress::default();
        let report = execute_wait(
            &run_spec(WaitCondition::Appeared, Duration::from_secs(10)),
            &mut backend,
            &clock,
            &borrowed,
            &mut progress,
        );
        assert_eq!(report["status"], "interrupted");
        assert_eq!(
            report["machine_error"]["stable_exit_code"],
            WAIT_INTERRUPTED_EXIT_CODE
        );
    }

    #[test]
    fn progress_is_only_emitted_when_observed_state_changes() {
        let mut backend = FakeBackend::snapshots([
            WaitSnapshot::absent(),
            WaitSnapshot::absent(),
            run_snapshot_for("running"),
            run_snapshot_for("running"),
            run_snapshot_for("completed"),
        ]);
        let (_, progress) = execute(
            &run_spec(WaitCondition::Terminal, Duration::from_secs(10)),
            &mut backend,
        );
        assert_eq!(progress, vec!["absent", "running", "completed"]);
    }
}
