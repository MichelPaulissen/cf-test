use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

pub(super) fn child_stderr_suffix(child: &mut Child) -> String {
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        let _ = stream.read_to_string(&mut stderr);
    }
    let stderr = stderr.trim();
    if stderr.is_empty() {
        String::new()
    } else {
        format!("; worker stderr: {stderr}")
    }
}

pub(super) fn local_tool_command(
    env_var: &str,
    binary: &str,
    package: &str,
    repo: &Path,
) -> Command {
    if let Some(path) = std::env::var_os(env_var) {
        return Command::new(path);
    }
    let current_exe = std::env::current_exe().ok();
    if !workspace_development_executable(current_exe.as_deref(), repo) {
        if let Some(path) = sibling_tool_path(current_exe.as_deref(), binary) {
            return Command::new(path);
        }
    }

    // A workspace-built adapter must ask Cargo for the matching service binary:
    // a sibling executable can be older than the adapter even though both happen
    // to live in target/debug. Installed releases take the sibling path above.
    let mut command = Command::new("cargo");
    command.args(["run", "-q", "-p", package, "--bin", binary, "--"]);
    command
}

fn sibling_tool_path(current_exe: Option<&Path>, binary: &str) -> Option<PathBuf> {
    let mut sibling = current_exe?.to_path_buf();
    sibling.set_file_name(format!("{binary}{}", std::env::consts::EXE_SUFFIX));
    sibling.is_file().then_some(sibling)
}

fn workspace_development_executable(current_exe: Option<&Path>, repo: &Path) -> bool {
    let Some(current_exe) = current_exe else {
        return false;
    };
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                repo.join(path)
            }
        })
        .unwrap_or_else(|| repo.join("target"));
    current_exe.starts_with(target)
}
