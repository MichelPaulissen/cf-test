use clusterflux::prelude::*;
use clusterflux::serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, clusterflux::TaskArg)]
#[serde(crate = "clusterflux::serde")]
pub struct BuildInput {
    lane: String,
    source: SourceSnapshot,
}

#[clusterflux::task(capabilities = "command")]
pub async fn build_lane(input: BuildInput) -> Result<Artifact> {
    let source_root = input.source.mount()?;
    let output = fs::output(format!("{}.txt", input.lane))?;
    let command = if input.lane == "recovering" {
        "exit 23".to_owned()
    } else {
        format!("sleep 3; printf 'stable\n' > {}", output.as_str())
    };
    Command::new("sh")
        .args(["-c", command.as_str()])
        .cwd(source_root)
        .network_disabled()
        .run()
        .await?;
    fs::publish(&output).await
}

#[clusterflux::main]
pub async fn build() -> Result<Vec<Artifact>> {
    let source = source::current_project().snapshot().await?;
    let stable = clusterflux::spawn!(build_lane(BuildInput {
        lane: "stable".to_owned(),
        source: source.clone(),
    }))
    .on(clusterflux::env!("linux"))
    .await?;
    let recovering = clusterflux::spawn!(build_lane(BuildInput {
        lane: "recovering".to_owned(),
        source,
    }))
    .on(clusterflux::env!("linux"))
    .failure_policy(clusterflux::TaskFailurePolicy::AwaitOperator)
    .await?;
    Ok(vec![stable.join().await?, recovering.join().await?])
}
