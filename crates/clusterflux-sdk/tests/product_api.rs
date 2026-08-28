#[clusterflux::task]
async fn plus_one(value: i32) -> clusterflux::Result<i32> {
    Ok(value + 1)
}

#[test]
fn unified_spawn_keeps_ergonomics_and_reports_native_runtime_absence() {
    let result = futures_executor::block_on(async {
        clusterflux::spawn!(plus_one(41))
            .on(clusterflux::env!("linux"))
            .await
    });
    assert!(matches!(
        result,
        Err(clusterflux::Error::NotRunningInsideClusterflux)
    ));
}

#[test]
fn source_mount_and_command_failure_are_public_typed_contracts() {
    let source = clusterflux::SourceSnapshot {
        digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_owned(),
    };
    assert_eq!(source.mount().unwrap(), "/workspace");

    let error = clusterflux::Error::CommandFailed {
        program: "cc".to_owned(),
        status_code: Some(2),
        stdout: "out".to_owned(),
        stderr: "bad input".to_owned(),
        stdout_truncated: false,
        stderr_truncated: false,
    };
    assert!(error.to_string().contains("command"));
    assert!(error.to_string().contains("cc"));
}
