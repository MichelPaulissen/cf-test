use clusterflux::prelude::*;

/// Release-owned pre-process task. Its only authority is one fixed,
/// network-disabled command in the pinned compiler environment.
#[clusterflux::task(
    name = "clusterflux.system.compile-workflow",
    capabilities = "command"
)]
pub async fn compile_workflow() -> Result<()> {
    Command::new("/opt/clusterflux/bin/compile-workflow")
        .args([
            "/workspace/main.rs",
            "/clusterflux/output/bundle.json",
        ])
        .cwd("/workspace")
        .network_disabled()
        .run()
        .await?;
    Ok(())
}
