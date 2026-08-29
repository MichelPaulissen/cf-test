use super::*;
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse, TaskLogStream};
use std::sync::mpsc::{self, Receiver, SyncSender};
use wait_timeout::ChildExt;
use zeroize::Zeroize;

struct LiveLogChunk {
    stream: &'static str,
    offset: u64,
    source_bytes: u64,
    bytes: Vec<u8>,
    truncated: bool,
}

fn append_bounded_tail(tail: &mut Vec<u8>, bytes: &[u8], maximum: usize) {
    if maximum == 0 {
        tail.clear();
        return;
    }
    if bytes.len() >= maximum {
        tail.clear();
        tail.extend_from_slice(&bytes[bytes.len() - maximum..]);
        return;
    }
    let overflow = tail
        .len()
        .saturating_add(bytes.len())
        .saturating_sub(maximum);
    if overflow > 0 {
        tail.drain(..overflow);
    }
    tail.extend_from_slice(bytes);
}

fn redact_safe_live_log_prefix(
    pending: &[u8],
    configured_secrets: &[String],
    final_chunk: bool,
) -> Option<(usize, String)> {
    if pending.is_empty() {
        return None;
    }
    let secret_bytes = configured_secrets
        .iter()
        .filter(|secret| secret.len() >= 4)
        .map(String::as_bytes)
        .collect::<Vec<_>>();
    let maximum_secret_bytes = secret_bytes
        .iter()
        .map(|secret| secret.len())
        .max()
        .unwrap_or(0);
    if !final_chunk && pending.len() <= maximum_secret_bytes {
        return None;
    }
    let mut consumed = if final_chunk {
        pending.len()
    } else {
        pending.len() - maximum_secret_bytes
    };
    loop {
        let previous = consumed;
        for secret in &secret_bytes {
            if secret.len() > pending.len() {
                continue;
            }
            for start in 0..=pending.len() - secret.len() {
                let end = start + secret.len();
                if start < consumed && end > consumed && &pending[start..end] == *secret {
                    consumed = end;
                }
            }
        }
        if consumed == previous {
            break;
        }
    }
    if consumed == 0 {
        return None;
    }
    let text = redact_configured_values(
        String::from_utf8_lossy(&pending[..consumed]).into_owned(),
        configured_secrets,
    );
    Some((consumed, text))
}

pub(super) struct CoordinatorControlledProcessRunner {
    pub(super) args: Args,
    pub(super) process: String,
    pub(super) task: String,
    pub(super) node_private_key: String,
    pub(super) assignment_authority: clusterflux_core::AssignmentAuthority,
    pub(super) debug_control: Arc<WasmDebugControl>,
    pub(super) command_status: Arc<Mutex<Option<String>>>,
    pub(super) stdout_source_bytes: Arc<AtomicU64>,
    pub(super) stderr_source_bytes: Arc<AtomicU64>,
    pub(super) timeout: Duration,
    pub(super) configured_secrets: Vec<String>,
    pub(super) local_abort_requested: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
struct ContainerControl {
    runtime: String,
    name: String,
}

enum ExecutionControlPollError {
    Transient(String),
    Fatal(BackendError),
}

enum FrozenExecution {
    ContainerRuntime(ContainerControl),
    #[cfg(unix)]
    UnixProcessGroup(u32),
    #[cfg(windows)]
    WindowsProcesses(clusterflux_core::SuspendedWindowsProcesses),
}

impl Drop for CoordinatorControlledProcessRunner {
    fn drop(&mut self) {
        for secret in &mut self.configured_secrets {
            secret.zeroize();
        }
    }
}

impl CoordinatorControlledProcessRunner {
    const MAX_CAPTURE_BYTES: usize = 256 * 1024 + 1;
    const PODMAN_CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
    const EXECUTION_CONTROL_OUTAGE_GRACE: Duration = Duration::from_secs(30);
    const EXECUTION_CONTROL_RETRY_MAX_DELAY: Duration = Duration::from_secs(2);

    pub(super) fn new(
        host: &CoordinatorWasmTaskHost,
        timeout: Duration,
        configured_secrets: Vec<String>,
    ) -> Self {
        Self {
            args: host.args.clone(),
            process: host.process.clone(),
            task: host.parent_task.clone(),
            node_private_key: host.node_private_key.clone(),
            assignment_authority: host.assignment_authority.clone(),
            debug_control: Arc::clone(&host.debug_control),
            command_status: Arc::clone(&host.command_status),
            stdout_source_bytes: Arc::clone(&host.command_stdout_source_bytes),
            stderr_source_bytes: Arc::clone(&host.command_stderr_source_bytes),
            timeout,
            configured_secrets,
            local_abort_requested: Arc::clone(&host.abort_requested),
        }
    }

    fn set_command_status(&self, status: impl Into<String>) {
        if let Ok(mut current) = self.command_status.lock() {
            *current = Some(status.into());
        }
    }

    fn abort_requested(
        &self,
        session: &mut CoordinatorSession,
    ) -> Result<bool, ExecutionControlPollError> {
        let request = crate::node_identity::signed_node_assignment_request(
            &self.args,
            &self.node_private_key,
            &self.assignment_authority,
            "poll_task_control",
            CoordinatorRequest::PollTaskControl {
                tenant: self.args.tenant.clone(),
                project: self.args.project.clone(),
                process: self.process.clone(),
                node: self.args.node.clone(),
                task: self.task.clone(),
                child_tasks: Vec::new(),
            },
        )
        .map_err(|error| {
            ExecutionControlPollError::Fatal(BackendError::Command(error.to_string()))
        })?;
        let response = session.request(request).map_err(|error| {
            let message = format!("poll task control: {error}");
            if crate::coordinator_session::retryable_session_error(error.as_ref()) {
                ExecutionControlPollError::Transient(message)
            } else {
                ExecutionControlPollError::Fatal(BackendError::Command(message))
            }
        })?;
        match response {
            CoordinatorResponse::TaskControl {
                abort_requested, ..
            } => Ok(abort_requested),
            _ => Err(ExecutionControlPollError::Fatal(BackendError::Command(
                "coordinator returned an unexpected task-control response".to_owned(),
            ))),
        }
    }

    fn terminate_process_group(child: &mut std::process::Child) {
        #[cfg(unix)]
        {
            let process_group = -(child.id() as i32);
            // The child is placed in a new process group before exec, so this reaches
            // all native descendants. Podman containers are removed separately.
            unsafe {
                libc::kill(process_group, libc::SIGKILL);
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    fn container_control(command: &PodmanCommand) -> Option<ContainerControl> {
        if !matches!(command.program.as_str(), "podman" | "nerdctl")
            || command.args.first().map(String::as_str) != Some("run")
        {
            return None;
        }
        command
            .args
            .windows(2)
            .find(|arguments| arguments[0] == "--name")
            .map(|arguments| ContainerControl {
                runtime: command.program.clone(),
                name: arguments[1].clone(),
            })
    }

    fn set_container_paused(
        container: &ContainerControl,
        paused: bool,
    ) -> Result<(), BackendError> {
        let action = if paused { "pause" } else { "unpause" };
        let (status, _, stderr) =
            Self::bounded_container_output(&container.runtime, &[action, &container.name])?;
        if !status.success() {
            return Err(BackendError::Command(format!(
                "`{} {action}` failed for container `{}`: {}",
                container.runtime,
                container.name,
                stderr.trim()
            )));
        }

        let (inspection_status, observed, inspection_stderr) = Self::bounded_container_output(
            &container.runtime,
            &["inspect", "--format", "{{.State.Paused}}", &container.name],
        )?;
        let expected = if paused { "true" } else { "false" };
        if !inspection_status.success() || observed.trim() != expected {
            return Err(BackendError::Command(format!(
                "container `{}` did not verify as {} after `{} {action}`: status={:?} stdout={} stderr={}",
                container.name,
                if paused { "paused" } else { "running" },
                container.runtime,
                inspection_status.code(),
                observed.trim(),
                inspection_stderr.trim()
            )));
        }
        Ok(())
    }

    fn bounded_container_output(
        runtime: &str,
        arguments: &[&str],
    ) -> Result<(std::process::ExitStatus, String, String), BackendError> {
        let mut child = std::process::Command::new(runtime)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                BackendError::Command(format!("start {runtime} container control: {error}"))
            })?;
        let status = match child.wait_timeout(Self::PODMAN_CONTROL_TIMEOUT) {
            Ok(Some(status)) => status,
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(BackendError::Command(format!(
                    "{runtime} container control exceeded {} ms",
                    Self::PODMAN_CONTROL_TIMEOUT.as_millis()
                )));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(BackendError::Command(format!(
                    "wait for {runtime} container control: {error}"
                )));
            }
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if let Some(reader) = child.stdout.take() {
            reader
                .take(64 * 1024)
                .read_to_end(&mut stdout)
                .map_err(|error| BackendError::Command(error.to_string()))?;
        }
        if let Some(reader) = child.stderr.take() {
            reader
                .take(64 * 1024)
                .read_to_end(&mut stderr)
                .map_err(|error| BackendError::Command(error.to_string()))?;
        }
        Ok((
            status,
            String::from_utf8_lossy(&stdout).into_owned(),
            String::from_utf8_lossy(&stderr).into_owned(),
        ))
    }

    fn terminate_execution(child: &mut std::process::Child, container: Option<&ContainerControl>) {
        if let Some(container) = container {
            let _ = Self::bounded_container_output(&container.runtime, &["kill", &container.name]);
            let _ = Self::bounded_container_output(
                &container.runtime,
                &["rm", "--force", &container.name],
            );
        }
        Self::terminate_process_group(child);
    }

    fn freeze_execution(
        child: &std::process::Child,
        container: Option<&ContainerControl>,
    ) -> Result<FrozenExecution, BackendError> {
        if let Some(container) = container {
            #[cfg(windows)]
            if container.runtime == "nerdctl" {
                return Self::freeze_windows_container(container)
                    .map(FrozenExecution::WindowsProcesses);
            }
            Self::set_container_paused(container, true)?;
            return Ok(FrozenExecution::ContainerRuntime(container.clone()));
        }
        #[cfg(unix)]
        {
            Self::freeze_process_group(child)?;
            Ok(FrozenExecution::UnixProcessGroup(child.id()))
        }
        #[cfg(not(unix))]
        {
            let _ = child;
            Err(BackendError::Command(
                "native debug freeze requires Unix process groups".to_owned(),
            ))
        }
    }

    fn resume_execution(frozen: &mut FrozenExecution) -> Result<(), BackendError> {
        match frozen {
            FrozenExecution::ContainerRuntime(container) => {
                Self::set_container_paused(container, false)
            }
            #[cfg(unix)]
            FrozenExecution::UnixProcessGroup(process_id) => {
                Self::resume_process_group_id(*process_id)
            }
            #[cfg(windows)]
            FrozenExecution::WindowsProcesses(processes) => {
                processes.resume().map_err(BackendError::Command)
            }
        }
    }

    #[cfg(windows)]
    fn freeze_windows_container(
        container: &ContainerControl,
    ) -> Result<clusterflux_core::SuspendedWindowsProcesses, BackendError> {
        const MAX_STABILIZATION_PASSES: usize = 8;
        let root_process_id = Self::windows_container_entry_process_id(container)?;
        let mut suspended = clusterflux_core::SuspendedWindowsProcesses::new();
        for _ in 0..MAX_STABILIZATION_PASSES {
            let added = suspended
                .suspend_process_tree(root_process_id)
                .map_err(BackendError::Command)?;
            if added == 0 {
                return Ok(suspended);
            }
        }
        Err(BackendError::Command(format!(
            "Windows container `{}` did not reach a stable all-thread suspension after {MAX_STABILIZATION_PASSES} passes",
            container.name
        )))
    }

    #[cfg(windows)]
    fn windows_container_entry_process_id(
        container: &ContainerControl,
    ) -> Result<u32, BackendError> {
        let (status, stdout, stderr) = Self::bounded_container_output(
            &container.runtime,
            &["inspect", "--format", "{{.State.Pid}}", &container.name],
        )?;
        if !status.success() {
            return Err(BackendError::Command(format!(
                "resolve Windows task entry process for `{}`: {}",
                container.name,
                stderr.trim()
            )));
        }
        stdout.trim().parse::<u32>().map_err(|_| {
            BackendError::Command(format!(
                "nerdctl returned invalid Windows task entry PID `{}`",
                stdout.trim()
            ))
        })
    }

    #[cfg(unix)]
    fn freeze_process_group(child: &std::process::Child) -> Result<(), BackendError> {
        let process_group = -(child.id() as i32);
        let result = unsafe { libc::kill(process_group, libc::SIGSTOP) };
        if result == 0 {
            Ok(())
        } else {
            Err(BackendError::Command(format!(
                "failed to freeze native process group {}: {}",
                child.id(),
                std::io::Error::last_os_error()
            )))
        }
    }

    #[cfg(unix)]
    fn resume_process_group_id(process_id: u32) -> Result<(), BackendError> {
        let process_group = -(process_id as i32);
        let result = unsafe { libc::kill(process_group, libc::SIGCONT) };
        if result == 0 {
            Ok(())
        } else {
            Err(BackendError::Command(format!(
                "failed to resume native process group {}: {}",
                process_id,
                std::io::Error::last_os_error()
            )))
        }
    }

    fn drain_bounded(
        mut reader: impl Read + Send + 'static,
        maximum: usize,
        stream: &'static str,
        sender: SyncSender<LiveLogChunk>,
        configured_secrets: Vec<String>,
        source_bytes_total: Arc<AtomicU64>,
    ) -> thread::JoinHandle<Result<Vec<u8>, String>> {
        thread::spawn(move || {
            let mut captured = Vec::new();
            let mut buffer = [0_u8; 16 * 1024];
            let stream_base = source_bytes_total.load(Ordering::Relaxed);
            let mut source_bytes_read = 0_u64;
            let mut pending_offset = stream_base;
            let mut pending = Vec::new();
            loop {
                let count = reader
                    .read(&mut buffer)
                    .map_err(|error| error.to_string())?;
                if count == 0 {
                    break;
                }
                let _ = source_bytes_total.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |current| Some(current.saturating_add(count as u64)),
                );
                source_bytes_read = source_bytes_read.saturating_add(count as u64);
                append_bounded_tail(&mut captured, &buffer[..count], maximum);
                pending.extend_from_slice(&buffer[..count]);
                if let Some((consumed, text)) =
                    redact_safe_live_log_prefix(&pending, &configured_secrets, false)
                {
                    let _ = sender.try_send(LiveLogChunk {
                        stream,
                        offset: pending_offset,
                        source_bytes: consumed as u64,
                        bytes: text.into_bytes(),
                        truncated: false,
                    });
                    pending.drain(..consumed);
                    pending_offset = pending_offset.saturating_add(consumed as u64);
                }
            }
            if let Some((consumed, text)) =
                redact_safe_live_log_prefix(&pending, &configured_secrets, true)
            {
                let _ = sender.try_send(LiveLogChunk {
                    stream,
                    offset: pending_offset,
                    source_bytes: consumed as u64,
                    bytes: text.into_bytes(),
                    truncated: false,
                });
            }
            if source_bytes_read > maximum as u64 {
                let _ = sender.try_send(LiveLogChunk {
                    stream,
                    offset: stream_base.saturating_add(source_bytes_read),
                    source_bytes: 0,
                    bytes: b"[log output truncated at node capture limit]".to_vec(),
                    truncated: true,
                });
            }
            Ok(captured)
        })
    }

    fn spawn_live_log_reporter(&self, receiver: Receiver<LiveLogChunk>) -> thread::JoinHandle<()> {
        let args = self.args.clone();
        let process = self.process.clone();
        let task = self.task.clone();
        let node_private_key = self.node_private_key.clone();
        let assignment_authority = self.assignment_authority.clone();
        let configured_secrets = self.configured_secrets.clone();
        let command_status = Arc::clone(&self.command_status);
        thread::spawn(move || {
            let mut log_session = None;
            let mut delivery_available = true;
            while let Ok(chunk) = receiver.recv() {
                if !delivery_available {
                    continue;
                }
                let mut text = String::from_utf8_lossy(&chunk.bytes).into_owned();
                text = redact_configured_values(text, &configured_secrets);
                let mut delivered = false;
                for _ in 0..2 {
                    if log_session.is_none() {
                        log_session = CoordinatorSession::connect_with_timeouts(
                            &args.coordinator,
                            Duration::from_millis(500),
                            Duration::from_millis(500),
                        )
                        .ok();
                    }
                    let Some(session) = log_session.as_mut() else {
                        continue;
                    };
                    let request = crate::node_identity::signed_node_assignment_request(
                        &args,
                        &node_private_key,
                        &assignment_authority,
                        "report_task_log_chunk",
                        CoordinatorRequest::ReportTaskLogChunk {
                            tenant: args.tenant.clone(),
                            project: args.project.clone(),
                            process: process.clone(),
                            node: args.node.clone(),
                            task: task.clone(),
                            stream: match chunk.stream {
                                "stdout" => TaskLogStream::Stdout,
                                "stderr" => TaskLogStream::Stderr,
                                _ => return,
                            },
                            offset: chunk.offset,
                            source_bytes: chunk.source_bytes,
                            text: text.clone(),
                            truncated: chunk.truncated,
                        },
                    );
                    let result = match request {
                        Ok(request) => session
                            .request(request)
                            .map(|_| ())
                            .map_err(|error| error.to_string()),
                        Err(error) => Err(error.to_string()),
                    };
                    match result {
                        Ok(()) => {
                            delivered = true;
                            break;
                        }
                        Err(_) => {
                            log_session = None;
                        }
                    }
                }
                if !delivered {
                    delivery_available = false;
                    if let Ok(mut current) = command_status.lock() {
                        *current = Some(
                            "live log delivery was interrupted; final bounded output remains available"
                                .to_owned(),
                        );
                    }
                }
            }
        })
    }
}

impl ProcessRunner for CoordinatorControlledProcessRunner {
    fn run(&mut self, command: &PodmanCommand) -> Result<ProcessOutput, BackendError> {
        let container = Self::container_control(command);
        let execution_kind = if container.is_some() {
            "container command"
        } else if matches!(command.program.as_str(), "podman" | "nerdctl") {
            "container runtime command"
        } else {
            "dangerous native command"
        };
        self.set_command_status(format!(
            "starting {execution_kind}: {} {}",
            command.program,
            command.args.join(" ")
        ));
        let mut process = std::process::Command::new(&command.program);
        process
            .args(&command.args)
            .envs(&command.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(working_directory) = &command.working_directory {
            process.current_dir(working_directory);
        }
        #[cfg(unix)]
        process.process_group(0);
        let mut child = process
            .spawn()
            .map_err(|error| BackendError::Command(error.to_string()))?;
        self.set_command_status(format!(
            "running {execution_kind} pid {}: {} {}",
            child.id(),
            command.program,
            command.args.join(" ")
        ));
        let (live_log_sender, live_log_receiver) = mpsc::sync_channel(64);
        let stdout = Self::drain_bounded(
            child
                .stdout
                .take()
                .ok_or_else(|| BackendError::Command("command stdout pipe missing".to_owned()))?,
            Self::MAX_CAPTURE_BYTES,
            "stdout",
            live_log_sender.clone(),
            self.configured_secrets.clone(),
            Arc::clone(&self.stdout_source_bytes),
        );
        let stderr = Self::drain_bounded(
            child
                .stderr
                .take()
                .ok_or_else(|| BackendError::Command("command stderr pipe missing".to_owned()))?,
            Self::MAX_CAPTURE_BYTES,
            "stderr",
            live_log_sender,
            self.configured_secrets.clone(),
            Arc::clone(&self.stderr_source_bytes),
        );
        let live_log_reporter = self.spawn_live_log_reporter(live_log_receiver);
        let mut session = match CoordinatorSession::connect_with_timeouts(
            &self.args.coordinator,
            Duration::from_millis(500),
            Duration::from_millis(500),
        ) {
            Ok(session) => session,
            Err(error) => {
                Self::terminate_execution(&mut child, container.as_ref());
                let _ = stdout.join();
                let _ = stderr.join();
                let _ = live_log_reporter.join();
                return Err(BackendError::Command(format!(
                    "establish execution control channel: {error}"
                )));
            }
        };

        let mut frozen_execution: Option<(u64, FrozenExecution)> = None;
        let mut control_outage_started = None;
        let mut next_control_poll = Instant::now();
        let mut control_retry_delay = Duration::from_millis(100);
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(error) => {
                    Self::terminate_execution(&mut child, container.as_ref());
                    let _ = stdout.join();
                    let _ = stderr.join();
                    let _ = live_log_reporter.join();
                    return Err(BackendError::Command(error.to_string()));
                }
            }
            if started.elapsed() >= self.timeout {
                self.set_command_status(format!(
                    "{execution_kind} pid {} exceeded wall-clock timeout of {} ms",
                    child.id(),
                    self.timeout.as_millis()
                ));
                Self::terminate_execution(&mut child, container.as_ref());
                let _ = stdout.join();
                let _ = stderr.join();
                let _ = live_log_reporter.join();
                return Err(BackendError::Command(format!(
                    "{execution_kind} exceeded wall-clock timeout of {} ms",
                    self.timeout.as_millis()
                )));
            }
            if self.local_abort_requested.load(Ordering::Acquire) {
                self.set_command_status(format!(
                    "aborting {execution_kind} pid {} at local lane shutdown",
                    child.id()
                ));
                Self::terminate_execution(&mut child, container.as_ref());
                let _ = stdout.join();
                let _ = stderr.join();
                let _ = live_log_reporter.join();
                return Err(BackendError::Cancelled(
                    "Wasm lane requested local command cancellation".to_owned(),
                ));
            }
            let control_now = Instant::now();
            if control_now >= next_control_poll {
                match self.abort_requested(&mut session) {
                    Ok(true) => {
                        self.set_command_status(format!(
                            "aborting {execution_kind} pid {} at coordinator request",
                            child.id()
                        ));
                        Self::terminate_execution(&mut child, container.as_ref());
                        let _ = stdout.join();
                        let _ = stderr.join();
                        let _ = live_log_reporter.join();
                        return Err(BackendError::Cancelled(
                            "coordinator requested cancellation or abort".to_owned(),
                        ));
                    }
                    Ok(false) => {
                        if control_outage_started.take().is_some() {
                            self.set_command_status(format!(
                                "running {execution_kind} pid {} after execution control reconnected",
                                child.id()
                            ));
                        }
                        control_retry_delay = Duration::from_millis(100);
                    }
                    Err(ExecutionControlPollError::Transient(error)) => {
                        let outage_started = *control_outage_started.get_or_insert(control_now);
                        let outage_duration = control_now.duration_since(outage_started);
                        if outage_duration >= Self::EXECUTION_CONTROL_OUTAGE_GRACE {
                            Self::terminate_execution(&mut child, container.as_ref());
                            let _ = stdout.join();
                            let _ = stderr.join();
                            let _ = live_log_reporter.join();
                            return Err(BackendError::Command(format!(
                                "execution control was unavailable for {} ms; last error: {error}",
                                outage_duration.as_millis()
                            )));
                        }
                        self.set_command_status(format!(
                            "{execution_kind} pid {} is running while execution control reconnects: {error}",
                            child.id()
                        ));
                        match CoordinatorSession::connect_with_timeouts(
                            &self.args.coordinator,
                            Duration::from_millis(500),
                            Duration::from_millis(500),
                        ) {
                            Ok(reconnected) => session = reconnected,
                            Err(reconnect_error)
                                if crate::coordinator_session::retryable_session_error(
                                    reconnect_error.as_ref(),
                                ) => {}
                            Err(reconnect_error) => {
                                Self::terminate_execution(&mut child, container.as_ref());
                                let _ = stdout.join();
                                let _ = stderr.join();
                                let _ = live_log_reporter.join();
                                return Err(BackendError::Command(format!(
                                    "reestablish execution control channel: {reconnect_error}"
                                )));
                            }
                        }
                        next_control_poll = Instant::now() + control_retry_delay;
                        control_retry_delay = control_retry_delay
                            .saturating_mul(2)
                            .min(Self::EXECUTION_CONTROL_RETRY_MAX_DELAY);
                    }
                    Err(ExecutionControlPollError::Fatal(error)) => {
                        Self::terminate_execution(&mut child, container.as_ref());
                        let _ = stdout.join();
                        let _ = stderr.join();
                        let _ = live_log_reporter.join();
                        return Err(error);
                    }
                }
            }
            if let Some(epoch) = self.debug_control.requested_epoch() {
                if self.debug_control.resume_requested(epoch) {
                    if frozen_execution.as_ref().map(|(frozen, _)| *frozen) == Some(epoch) {
                        let (_, frozen) = frozen_execution
                            .as_mut()
                            .expect("matching frozen epoch has execution state");
                        match Self::resume_execution(frozen) {
                            Ok(()) => {
                                self.set_command_status(format!(
                                    "running command pid {} after debug epoch {epoch} resumed",
                                    child.id()
                                ));
                                self.debug_control.mark_running(epoch);
                                frozen_execution = None;
                            }
                            Err(error) => self.set_command_status(format!(
                                "debug epoch {epoch} resume is pending: {error}"
                            )),
                        }
                    }
                } else if frozen_execution.as_ref().map(|(frozen, _)| *frozen) != Some(epoch)
                    && self.debug_control.frozen_epoch() != Some(epoch)
                {
                    match Self::freeze_execution(&child, container.as_ref()) {
                        Ok(frozen) => {
                            self.set_command_status(format!(
                                "frozen command pid {} for debug epoch {epoch}",
                                child.id()
                            ));
                            self.debug_control.mark_frozen(epoch);
                            frozen_execution = Some((epoch, frozen));
                        }
                        Err(error) => self.set_command_status(format!(
                            "debug epoch {epoch} freeze is pending: {error}"
                        )),
                    }
                }
            }
            thread::sleep(Duration::from_millis(50));
        };
        let stdout = stdout
            .join()
            .map_err(|_| BackendError::Command("stdout reader panicked".to_owned()))?
            .map_err(BackendError::Command)?;
        let stderr = stderr
            .join()
            .map_err(|_| BackendError::Command("stderr reader panicked".to_owned()))?
            .map_err(BackendError::Command)?;
        live_log_reporter
            .join()
            .map_err(|_| BackendError::Command("live log reporter panicked".to_owned()))?;
        self.set_command_status(format!(
            "{execution_kind} exited with status {:?}",
            status.code()
        ));
        Ok(ProcessOutput {
            status_code: status.code(),
            stdout,
            stderr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{redact_safe_live_log_prefix, CoordinatorControlledProcessRunner};
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{mpsc, Arc};

    #[test]
    fn live_log_redaction_holds_boundaries_until_split_secrets_are_complete() {
        let secrets = vec!["correct-horse".to_owned()];
        let mut pending = b"prefix correct-".to_vec();
        let (consumed, first) = redact_safe_live_log_prefix(&pending, &secrets, false).unwrap();
        pending.drain(..consumed);
        pending.extend_from_slice(b"horse suffix");
        let (_, second) = redact_safe_live_log_prefix(&pending, &secrets, true).unwrap();

        let combined = format!("{first}{second}");
        assert_eq!(combined, "prefix [REDACTED] suffix");
        assert!(!combined.contains("correct-"));
        assert!(!combined.contains("horse"));
    }

    #[test]
    fn live_log_redaction_handles_output_shorter_than_a_configured_secret() {
        let secrets = vec!["x".repeat(93)];
        let output = b"short command output";

        assert_eq!(redact_safe_live_log_prefix(output, &secrets, false), None);
        assert_eq!(
            redact_safe_live_log_prefix(output, &secrets, true),
            Some((output.len(), "short command output".to_owned()))
        );
    }

    #[test]
    fn bounded_capture_retains_the_real_tail_and_complete_source_byte_count() {
        let source_bytes = Arc::new(AtomicU64::new(5));
        let (sender, receiver) = mpsc::sync_channel(8);
        let reader = CoordinatorControlledProcessRunner::drain_bounded(
            Cursor::new(b"0123456789abcdefghijklmnopqrstuv".to_vec()),
            8,
            "stdout",
            sender,
            Vec::new(),
            Arc::clone(&source_bytes),
        );
        let captured = reader.join().unwrap().unwrap();
        let chunks = receiver.into_iter().collect::<Vec<_>>();

        assert_eq!(captured, b"opqrstuv");
        assert_eq!(source_bytes.load(Ordering::Relaxed), 37);
        assert_eq!(
            chunks.iter().map(|chunk| chunk.source_bytes).sum::<u64>(),
            32
        );
        assert_eq!(chunks[0].offset, 5);
        assert_eq!(chunks.last().unwrap().offset, 37);
        assert!(chunks.iter().any(|chunk| chunk.truncated));
    }
}
