use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::Parser;
use clusterflux_core::Os;
use clusterflux_node::{
    LinuxRootlessPodmanBackend, StdProcessRunner, WindowsContainerdNerdctlBackend,
};
use serde::Serialize;

#[derive(Parser)]
#[command(
    name = "clusterflux-environment-setup",
    version,
    about = "Prebuild immutable Clusterflux task environments"
)]
struct Args {
    #[arg(long, value_name = "PATH")]
    project_root: PathBuf,
    #[arg(long = "name", value_name = "ENVIRONMENT")]
    names: Vec<String>,
}

#[derive(Serialize)]
struct MaterializedRecord {
    name: String,
    definition_digest: clusterflux_core::Digest,
    local_image: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let project_root = args.project_root.canonicalize().map_err(|error| {
        format!(
            "resolve project root `{}`: {error}",
            args.project_root.display()
        )
    })?;
    let materialized_source =
        clusterflux_source::materialize_clean_local_git_revision(&project_root)?;
    let discovery_root = materialized_source
        .as_ref()
        .map_or(project_root.as_path(), |source| source.root());
    std::env::set_current_dir(discovery_root).map_err(|error| {
        format!(
            "enter project root `{}` for environment materialization: {error}",
            discovery_root.display()
        )
    })?;
    let selected = args.names.into_iter().collect::<BTreeSet<_>>();
    let environments = clusterflux_core::discover_environments(discovery_root)?;
    let discovered = environments
        .iter()
        .map(|environment| environment.name.as_str())
        .collect::<BTreeSet<_>>();
    if let Some(missing) = selected
        .iter()
        .find(|name| !discovered.contains(name.as_str()))
    {
        return Err(format!(
            "environment `{missing}` was not discovered under {}/envs",
            discovery_root.display()
        )
        .into());
    }
    let mut records = Vec::new();
    let mut runner = StdProcessRunner;
    for environment in environments
        .into_iter()
        .filter(|environment| selected.is_empty() || selected.contains(&environment.name))
    {
        if environment.requirements.os.as_ref() != Some(&Os::current()) {
            if selected.contains(&environment.name) {
                return Err(format!(
                    "environment `{}` requires {:?}, but this node is {:?}",
                    environment.name,
                    environment.requirements.os,
                    Os::current()
                )
                .into());
            }
            continue;
        }
        let materialized = match Os::current() {
            Os::Linux => LinuxRootlessPodmanBackend
                .execute_environment_materialization(&environment, &mut runner)?,
            Os::Windows => WindowsContainerdNerdctlBackend
                .execute_environment_materialization(&environment, &mut runner)?,
            Os::Macos | Os::Other(_) => {
                return Err("this platform has no container environment backend".into())
            }
        };
        records.push(MaterializedRecord {
            name: environment.name,
            definition_digest: environment.digest,
            local_image: materialized.local_reference,
        });
    }
    if records.is_empty() {
        return Err("no task environments were selected".into());
    }
    println!("{}", serde_json::to_string_pretty(&records)?);
    eprintln!(
        "Environment setup complete. Restart the Clusterflux node so it advertises the refreshed cache inventory."
    );
    Ok(())
}
