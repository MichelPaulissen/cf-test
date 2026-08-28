use serde::{Deserialize, Serialize};

use crate::{
    Digest, WorkflowCompilerResourcePolicy, MAX_WORKFLOW_SOURCE_BYTES,
    SUPPORTED_WORKFLOW_SDK_VERSION, SUPPORTED_WORKFLOW_SERDE_VERSION, WASM_TASK_ABI_VERSION,
};

pub const WORKFLOW_COMPILER_SYSTEM_BUNDLE_ID: &str = "clusterflux.system.compile-workflow.v1";
pub const WORKFLOW_COMPILER_SYSTEM_TASK_NAME: &str = "clusterflux.system.compile-workflow";

/// Release-owned Wasm bytes shared by coordinator and node distributions.
pub static WORKFLOW_COMPILER_SYSTEM_BUNDLE_BYTES: &[u8] =
    include_bytes!("../assets/workflow-compiler-system-bundle.wasm");
pub const WORKFLOW_COMPILER_RUST_TOOLCHAIN: &str = env!("CLUSTERFLUX_COMPILER_RUST_RELEASE");
pub const WORKFLOW_COMPILER_WASM_TARGET: &str = env!("CLUSTERFLUX_COMPILER_WASM_TARGET");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemCompilerBundleManifest {
    pub bundle_id: String,
    pub bundle_digest: Digest,
    pub environment_digest: Digest,
    pub sdk_digest: Digest,
    pub rust_toolchain: String,
    pub sdk_abi_version: u32,
    pub wasm_target: String,
    pub supported_os: String,
    pub supported_arch: String,
    pub max_source_bytes: usize,
    pub max_output_bytes: usize,
}

pub fn workflow_compiler_system_bundle_digest() -> Digest {
    Digest::sha256(WORKFLOW_COMPILER_SYSTEM_BUNDLE_BYTES)
}

pub fn workflow_compiler_environment_digest() -> Digest {
    Digest::from_sha256_hex(env!("CLUSTERFLUX_COMPILER_ENVIRONMENT_INPUT_DIGEST"))
        .expect("build script emits one SHA-256 environment input digest")
}

pub fn workflow_compiler_system_manifest() -> SystemCompilerBundleManifest {
    let resource_policy = WorkflowCompilerResourcePolicy::default();
    SystemCompilerBundleManifest {
        bundle_id: WORKFLOW_COMPILER_SYSTEM_BUNDLE_ID.to_owned(),
        bundle_digest: workflow_compiler_system_bundle_digest(),
        environment_digest: workflow_compiler_environment_digest(),
        sdk_digest: Digest::from_parts([
            b"clusterflux-system-compiler-sdk:v1".as_slice(),
            SUPPORTED_WORKFLOW_SDK_VERSION.as_bytes(),
            SUPPORTED_WORKFLOW_SERDE_VERSION.as_bytes(),
            WORKFLOW_COMPILER_RUST_TOOLCHAIN.as_bytes(),
        ]),
        rust_toolchain: WORKFLOW_COMPILER_RUST_TOOLCHAIN.to_owned(),
        sdk_abi_version: WASM_TASK_ABI_VERSION,
        wasm_target: WORKFLOW_COMPILER_WASM_TARGET.to_owned(),
        supported_os: std::env::consts::OS.to_owned(),
        supported_arch: std::env::consts::ARCH.to_owned(),
        max_source_bytes: MAX_WORKFLOW_SOURCE_BYTES,
        max_output_bytes: resource_policy.max_output_bytes,
    }
}
