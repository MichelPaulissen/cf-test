use clusterflux::prelude::*;

#[clusterflux::task(capabilities = "command")]
pub async fn compile(source: SourceSnapshot) -> Result<Artifact> {
    let executable = fs::output("hello-clusterflux")?;
    Command::new("cc")
        .args([
            "-Os",
            "-static",
            "-s",
            "fixture/hello-clusterflux.c",
            "-o",
            executable.as_str(),
        ])
        .cwd(source.mount()?)
        .env("SOURCE_DATE_EPOCH", "0")
        .network_disabled()
        .run()
        .await?;
    fs::publish(&executable).await
}

#[clusterflux::main]
pub async fn build() -> Result<Artifact> {
    let source = source::current_project().snapshot().await?;
    let compile = clusterflux::spawn!(compile(source))
        .on(clusterflux::env!("linux"))
        .await?;
    compile.join().await
}
