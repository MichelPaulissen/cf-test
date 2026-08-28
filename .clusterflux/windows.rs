use std::time::Duration;

use clusterflux::prelude::*;
use clusterflux::serde::{Deserialize, Serialize};

use crate::tasks::{PRODUCT_VERSION, WINDOWS_ARCHIVE_NAME};

#[derive(Clone, Serialize, Deserialize, clusterflux::TaskArg)]
#[serde(crate = "clusterflux::serde")]
pub struct WindowsReleaseInput {
    pub source: SourceSnapshot,
    pub commit_sha: String,
    pub version: String,
}

#[derive(Clone, Serialize, Deserialize, clusterflux::TaskArg)]
#[serde(crate = "clusterflux::serde")]
pub struct WindowsReleasePackage {
    pub version: String,
    pub commit_sha: String,
    pub source_snapshot: String,
    pub package: Artifact,
}

#[clusterflux::task(capabilities = "command,network,source_filesystem,source_git,vfs_artifacts")]
pub async fn build_windows_release_package(
    input: WindowsReleaseInput,
) -> Result<WindowsReleasePackage> {
    if input.version != PRODUCT_VERSION {
        return Err(clusterflux::Error::Argument(
            "Windows release input does not match the workflow product version".to_owned(),
        ));
    }
    let root = input.source.mount()?;
    let package = fs::output(WINDOWS_ARCHIVE_NAME)?;

    Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            r"packaging\build-windows-release.ps1",
            "-Commit",
            input.commit_sha.as_str(),
            "-SourceSnapshot",
            input.source.digest.as_str(),
            "-Version",
            input.version.as_str(),
            "-Output",
            package.as_str(),
        ])
        .cwd(root)
        .env("CARGO_HOME", r"C:\clusterflux\output\cargo-home")
        .env("CARGO_TARGET_DIR", r"C:\clusterflux\output\target")
        .env("CARGO_TERM_COLOR", "always")
        .env("CARGO_INCREMENTAL", "0")
        .env("RUSTFLAGS", "-C target-feature=+crt-static")
        .network_enabled()
        .timeout(Duration::from_secs(60 * 60))
        .run()
        .await?;

    Ok(WindowsReleasePackage {
        version: input.version,
        commit_sha: input.commit_sha,
        source_snapshot: input.source.digest,
        package: fs::publish(&package).await?,
    })
}
