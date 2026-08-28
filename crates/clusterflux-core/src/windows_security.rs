use std::path::Path;

/// Restrict a private file or directory to the current Windows user, SYSTEM,
/// and the local Administrators group.
#[cfg(windows)]
pub fn secure_private_path(path: &Path, directory: bool) -> std::io::Result<()> {
    let current_user_sid = current_windows_user_sid()?;
    let inheritance = if directory { "(OI)(CI)" } else { "" };
    let grants = [
        format!("*{current_user_sid}:{inheritance}F"),
        format!("*S-1-5-18:{inheritance}F"),
        format!("*S-1-5-32-544:{inheritance}F"),
    ];
    let output = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .args(&grants)
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "secure private Windows path {} failed with status {:?}: {}{}",
        path.display(),
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

#[cfg(windows)]
fn current_windows_user_sid() -> std::io::Result<String> {
    let output = std::process::Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "resolve current Windows user SID failed with status {:?}: {}{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let line = String::from_utf8(output.stdout)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    line.trim()
        .split(',')
        .nth(1)
        .map(|value| value.trim().trim_matches('"'))
        .filter(|value| {
            value.starts_with("S-1-")
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
        })
        .map(str::to_owned)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "whoami returned an invalid Windows user SID",
            )
        })
}

#[cfg(not(windows))]
pub fn secure_private_path(_path: &Path, _directory: bool) -> std::io::Result<()> {
    Ok(())
}
