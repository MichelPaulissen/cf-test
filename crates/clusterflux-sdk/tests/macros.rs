use futures_executor::block_on;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, clusterflux::TaskArg)]
struct CompoundBoundary {
    label: String,
    source: clusterflux::SourceSnapshot,
    optional_artifact: Option<clusterflux::Artifact>,
    artifacts: Vec<clusterflux::Artifact>,
    blobs: Vec<Option<clusterflux::Blob>>,
    vfs: clusterflux::Vfs,
}

#[clusterflux::main]
fn build_main() -> u32 {
    1
}

#[clusterflux::main(name = "release")]
fn release_main() -> u32 {
    2
}

#[clusterflux::task(name = "compile-linux", capabilities = "Command")]
fn compile_linux() -> u32 {
    41
}

#[clusterflux::task]
fn package_release() -> clusterflux::Artifact {
    clusterflux::Artifact {
        id: "artifact://package/release.tar.zst".to_owned(),
        digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_owned(),
        size_bytes: 0,
    }
}

#[clusterflux::main(name = "async-build")]
async fn async_build_main() -> Result<(), &'static str> {
    Ok(())
}

#[clusterflux::task(name = "async-compile")]
async fn async_compile(input: u32) -> Result<u32, &'static str> {
    Ok(input + 1)
}

#[clusterflux::task(name = "roundtrip-compound")]
async fn roundtrip_compound(input: CompoundBoundary) -> CompoundBoundary {
    input
}

#[test]
fn clusterflux_attributes_and_spawn_api_compile_for_rust_build_workflow() {
    let program = clusterflux::RegisteredProgram {
        entrypoints: &[
            __CLUSTERFLUX_ENTRYPOINT_BUILD_MAIN,
            __CLUSTERFLUX_ENTRYPOINT_RELEASE_MAIN,
        ],
        tasks: &[
            __CLUSTERFLUX_TASK_COMPILE_LINUX,
            __CLUSTERFLUX_TASK_PACKAGE_RELEASE,
        ],
    };
    assert_eq!(
        program.select_entrypoint("build").unwrap().function,
        "build_main"
    );
    assert_eq!(
        program.select_entrypoint("release").unwrap().function,
        "release_main"
    );
    assert_eq!(
        program.task("compile-linux").unwrap().function,
        "compile_linux"
    );
    let task = program.task("compile-linux").unwrap();
    assert!(task.stable_id.starts_with("sha256:"));
    assert_eq!(task.argument_schema, "");
    assert_eq!(task.result_schema, "u32");
    assert_eq!(task.required_capabilities, ["Command"]);
    assert!(task.restart_compatibility_hash.starts_with("sha256:"));
    assert_eq!(task.abi_version, 1);
    assert!(task.source_file.ends_with("macros.rs"));
    assert!(task.source_line > 0);
    assert_eq!(
        task.probe_symbol,
        format!(
            "clusterflux.probe.{}",
            task.stable_id.trim_start_matches("sha256:")
        )
    );
    assert!(task.bundle_manifest_entry);
    assert!(task.remotely_startable);
    let entrypoint = program.select_entrypoint("build").unwrap();
    assert!(entrypoint.stable_id.starts_with("sha256:"));
    assert_eq!(entrypoint.result_schema, "u32");
    assert_eq!(entrypoint.abi_version, 1);
    assert!(entrypoint.bundle_manifest_entry);

    let result = block_on(async {
        clusterflux::spawn::task(|| compile_linux() + build_main())
            .name("compile linux")
            .env(clusterflux::env!("linux"))
            .start()
            .await
    });

    assert!(matches!(
        result,
        Err(clusterflux::Error::NotRunningInsideClusterflux)
    ));
    assert_eq!(release_main(), 2);
}

#[test]
fn task_boundaries_accept_small_values_and_runtime_handles() {
    let small =
        clusterflux::validate_task_arg(&7_u32, clusterflux::TaskArgBudget::default()).unwrap();
    assert_eq!(small.kind, clusterflux::TaskArgKind::SmallSerialized);

    let artifact = package_release();
    let artifact = clusterflux::validate_task_arg(
        &artifact,
        clusterflux::TaskArgBudget {
            max_inline_bytes: 4,
        },
    )
    .unwrap();
    assert_eq!(artifact.kind, clusterflux::TaskArgKind::Handle);
}

#[test]
fn async_main_and_task_attributes_preserve_real_rust_futures_and_results() {
    assert_eq!(block_on(async_build_main()), Ok(()));
    assert_eq!(block_on(async_compile(41)), Ok(42));
    assert_eq!(
        __CLUSTERFLUX_ENTRYPOINT_ASYNC_BUILD_MAIN.name,
        "async-build"
    );
    assert_eq!(__CLUSTERFLUX_TASK_ASYNC_COMPILE.name, "async-compile");
}

#[test]
fn derived_compound_boundary_keeps_nested_handles_out_of_opaque_json() {
    let source = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let value = CompoundBoundary {
        label: "release".to_owned(),
        source: clusterflux::SourceSnapshot {
            digest: source.to_owned(),
        },
        optional_artifact: Some(clusterflux::Artifact {
            id: "optional.bin".to_owned(),
            digest: source.to_owned(),
            size_bytes: 0,
        }),
        artifacts: vec![
            clusterflux::Artifact {
                id: "one.bin".to_owned(),
                digest: source.to_owned(),
                size_bytes: 0,
            },
            clusterflux::Artifact {
                id: "two.bin".to_owned(),
                digest: source.to_owned(),
                size_bytes: 0,
            },
        ],
        blobs: vec![Some(clusterflux::Blob {
            digest: source.to_owned(),
        })],
        vfs: clusterflux::Vfs {
            digest: source.to_owned(),
        },
    };
    assert_eq!(block_on(roundtrip_compound(value.clone())), value);
    let boundary = clusterflux::TaskArg::task_boundary_value(&value).unwrap();
    let clusterflux::core::TaskBoundaryValue::Structured(structured) = boundary else {
        panic!("derived boundary must be structured");
    };
    assert_eq!(structured.handles.len(), 6);
    let inline = structured.value.to_string();
    assert!(!inline.contains(source));
    assert!(!inline.contains("optional.bin"));
    assert_eq!(
        clusterflux::core::TaskBoundaryValue::Structured(structured.clone()).source_snapshots(),
        vec![clusterflux::core::Digest::sha256([])]
    );
    assert_eq!(
        clusterflux::core::TaskBoundaryValue::Structured(structured.clone()).required_artifacts(),
        vec![
            clusterflux::core::ArtifactId::from("optional.bin"),
            clusterflux::core::ArtifactId::from("one.bin"),
            clusterflux::core::ArtifactId::from("two.bin"),
        ]
    );
    let decoded: CompoundBoundary =
        serde_json::from_value(structured.materialize().unwrap()).unwrap();
    assert_eq!(decoded, value);
}
