use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

pub(crate) fn command_available(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

pub(crate) fn command_nonce(prefix: &str) -> String {
    let now = unix_timestamp_nanos();
    format!("{prefix}-{now}-{}", std::process::id())
}

pub(crate) fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn unix_timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

pub(crate) fn sibling_binary(name: &str) -> Option<PathBuf> {
    let mut sibling = std::env::current_exe().ok()?;
    sibling.set_file_name(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    sibling.is_file().then_some(sibling)
}

pub(crate) fn dap_binary_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("CLUSTERFLUX_DAP_BIN") {
        return Ok(PathBuf::from(path));
    }
    if let Some(path) = sibling_binary("clusterflux-debug-dap") {
        return Ok(path);
    }
    let release = PathBuf::from("target/release").join(format!(
        "clusterflux-debug-dap{}",
        std::env::consts::EXE_SUFFIX
    ));
    if release.is_file() {
        return Ok(release);
    }
    let debug = PathBuf::from("target/debug").join(format!(
        "clusterflux-debug-dap{}",
        std::env::consts::EXE_SUFFIX
    ));
    if debug.is_file() {
        return Ok(debug);
    }
    anyhow::bail!("could not locate clusterflux-debug-dap; set CLUSTERFLUX_DAP_BIN")
}
