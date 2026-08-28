use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};
use serde_json::Value;

pub(super) struct LocalNodeWorker {
    pub(super) process_id: u32,
    child: Option<Child>,
}

impl LocalNodeWorker {
    pub(super) fn start(coordinator: &str, project: &Path, enrollment_grant: &str) -> Result<Self> {
        let mut command = node_command()?;
        command.args([
            "--coordinator",
            coordinator,
            "--tenant",
            "tenant",
            "--project-id",
            "project",
            "--node",
            "node-cli-local",
            "--enrollment-grant",
            enrollment_grant,
            "--worker",
            "--project-root",
        ]);
        command.arg(project);
        command.args(["--assignment-poll-ms", "100", "--no-workflow-compilation"]);
        command.stdout(Stdio::null());
        command.stderr(Stdio::inherit());
        let child = command.spawn().context("failed to spawn node process")?;
        let process_id = child.id();
        Ok(Self {
            process_id,
            child: Some(child),
        })
    }

    pub(super) fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for LocalNodeWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(super) struct LocalCoordinator {
    pub(super) address: String,
    pub(super) process_id: Option<u32>,
    child: Option<Child>,
}

impl LocalCoordinator {
    pub(super) fn external(address: &str) -> Self {
        Self {
            address: address.to_owned(),
            process_id: None,
            child: None,
        }
    }

    pub(super) fn start_ephemeral() -> Result<Self> {
        let mut command = coordinator_command()?;
        command.args(["--listen", "127.0.0.1:0", "--allow-local-trusted-loopback"]);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::inherit());

        let mut child = command
            .spawn()
            .context("failed to spawn local coordinator process")?;
        let process_id = child.id();
        let address = match read_coordinator_ready_address(&mut child) {
            Ok(address) => address,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };

        Ok(Self {
            address,
            process_id: Some(process_id),
            child: Some(child),
        })
    }
}

impl Drop for LocalCoordinator {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn read_coordinator_ready_address(child: &mut Child) -> Result<String> {
    let stdout = child
        .stdout
        .take()
        .context("local coordinator stdout was not captured")?;
    let mut ready_line = String::new();
    BufReader::new(stdout)
        .read_line(&mut ready_line)
        .context("failed to read local coordinator ready line")?;
    if ready_line.trim().is_empty() {
        anyhow::bail!("local coordinator exited before reporting its listen address");
    }
    let ready: Value =
        serde_json::from_str(&ready_line).context("local coordinator ready line was not JSON")?;
    ready
        .get("listen")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .context("local coordinator did not report a listen address")
}

fn node_command() -> Result<Command> {
    if let Some(path) = std::env::var_os("CLUSTERFLUX_NODE_BIN") {
        return Ok(Command::new(path));
    }

    let mut sibling = std::env::current_exe().context("cannot locate current executable")?;
    sibling.set_file_name(format!("clusterflux-node{}", std::env::consts::EXE_SUFFIX));
    if sibling.is_file() {
        return Ok(Command::new(sibling));
    }

    let mut command = Command::new("cargo");
    command.args([
        "run",
        "-q",
        "-p",
        "clusterflux-node",
        "--bin",
        "clusterflux-node",
        "--",
    ]);
    Ok(command)
}

fn coordinator_command() -> Result<Command> {
    if let Some(path) = std::env::var_os("CLUSTERFLUX_COORDINATOR_BIN") {
        return Ok(Command::new(path));
    }

    let mut sibling = std::env::current_exe().context("cannot locate current executable")?;
    sibling.set_file_name(format!(
        "clusterflux-coordinator{}",
        std::env::consts::EXE_SUFFIX
    ));
    if sibling.is_file() {
        return Ok(Command::new(sibling));
    }

    let mut command = Command::new("cargo");
    command.args([
        "run",
        "-q",
        "-p",
        "clusterflux-coordinator",
        "--bin",
        "clusterflux-coordinator",
        "--",
    ]);
    Ok(command)
}
