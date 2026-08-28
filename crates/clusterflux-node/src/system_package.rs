use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use clusterflux_core::{
    workflow_compiler_system_manifest, Digest, SystemCompilerBundleManifest,
    SUPPORTED_WORKFLOW_SDK_VERSION, SUPPORTED_WORKFLOW_SERDE_VERSION, WASM_TASK_ABI_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const SYSTEM_COMPILER_IMAGE_ARCHIVE: &str = "system-compiler-image.oci.tar";
pub const SYSTEM_BUNDLES_MANIFEST: &str = "system-bundles.json";
pub const COMPILER_ENVIRONMENT_MANIFEST: &str = "compiler-environment.json";
pub const COMPILER_IMAGE_DIGEST: &str = "compiler-image-digest.txt";
pub const SYSTEM_PACKAGE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledSystemBundlesManifest {
    pub schema_version: u32,
    pub coordinator_protocol_version: u64,
    pub wasm_task_abi_version: u32,
    pub bundles: Vec<InstalledSystemCompilerBundle>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledSystemCompilerBundle {
    pub manifest: SystemCompilerBundleManifest,
    pub compiler_image_reference: String,
    pub compiler_image_digest: Digest,
    pub compiler_image_archive: String,
    pub compiler_image_archive_digest: Digest,
    pub sdk_version: String,
    pub serde_version: String,
    pub serde_features: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledCompilerEnvironmentManifest {
    pub schema_version: u32,
    pub environment_digest: Digest,
    pub compiler_image_reference: String,
    pub compiler_image_digest: Digest,
    pub compiler_image_archive: String,
    pub compiler_image_archive_digest: Digest,
    pub rust_toolchain: String,
    pub sdk_version: String,
    pub sdk_digest: Digest,
    pub serde_version: String,
    pub serde_features: Vec<String>,
    pub supported_os: String,
    pub supported_arch: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSystemCompilerPackage {
    pub share_dir: PathBuf,
    pub archive: PathBuf,
    pub image_reference: String,
    pub image_digest: Digest,
    pub environment_digest: Digest,
    pub archive_digest: Digest,
}

pub fn write_system_compiler_manifests(
    share_dir: &Path,
    image_digest: Digest,
) -> Result<VerifiedSystemCompilerPackage, String> {
    if !image_digest.is_valid_sha256() {
        return Err("compiler image ID is not a valid SHA-256 digest".to_owned());
    }
    fs::create_dir_all(share_dir)
        .map_err(|error| format!("create compiler package directory: {error}"))?;
    let archive = share_dir.join(SYSTEM_COMPILER_IMAGE_ARCHIVE);
    let archive_digest = sha256_file(&archive)?;
    let release = workflow_compiler_system_manifest();
    let image_reference = image_digest.to_string();
    let bundle = InstalledSystemCompilerBundle {
        manifest: release.clone(),
        compiler_image_reference: image_reference.clone(),
        compiler_image_digest: image_digest.clone(),
        compiler_image_archive: SYSTEM_COMPILER_IMAGE_ARCHIVE.to_owned(),
        compiler_image_archive_digest: archive_digest.clone(),
        sdk_version: SUPPORTED_WORKFLOW_SDK_VERSION.to_owned(),
        serde_version: SUPPORTED_WORKFLOW_SERDE_VERSION.to_owned(),
        serde_features: vec!["derive".to_owned()],
    };
    let bundles = InstalledSystemBundlesManifest {
        schema_version: SYSTEM_PACKAGE_SCHEMA_VERSION,
        coordinator_protocol_version: clusterflux_protocol::COORDINATOR_PROTOCOL_VERSION,
        wasm_task_abi_version: WASM_TASK_ABI_VERSION,
        bundles: vec![bundle],
    };
    let environment = InstalledCompilerEnvironmentManifest {
        schema_version: SYSTEM_PACKAGE_SCHEMA_VERSION,
        environment_digest: release.environment_digest.clone(),
        compiler_image_reference: image_reference,
        compiler_image_digest: image_digest,
        compiler_image_archive: SYSTEM_COMPILER_IMAGE_ARCHIVE.to_owned(),
        compiler_image_archive_digest: archive_digest,
        rust_toolchain: release.rust_toolchain.clone(),
        sdk_version: SUPPORTED_WORKFLOW_SDK_VERSION.to_owned(),
        sdk_digest: release.sdk_digest.clone(),
        serde_version: SUPPORTED_WORKFLOW_SERDE_VERSION.to_owned(),
        serde_features: vec!["derive".to_owned()],
        supported_os: release.supported_os.clone(),
        supported_arch: release.supported_arch.clone(),
    };
    write_json(&share_dir.join(SYSTEM_BUNDLES_MANIFEST), &bundles)?;
    write_json(&share_dir.join(COMPILER_ENVIRONMENT_MANIFEST), &environment)?;
    fs::write(
        share_dir.join(COMPILER_IMAGE_DIGEST),
        format!("{}\n", environment.compiler_image_digest),
    )
    .map_err(|error| format!("write compiler image digest: {error}"))?;
    verify_system_compiler_package(share_dir)
}

pub fn inspect_system_compiler_package(
    share_dir: &Path,
) -> Result<VerifiedSystemCompilerPackage, String> {
    let bundles: InstalledSystemBundlesManifest = read_json(
        &share_dir.join(SYSTEM_BUNDLES_MANIFEST),
        "system bundle manifest",
    )?;
    let environment: InstalledCompilerEnvironmentManifest = read_json(
        &share_dir.join(COMPILER_ENVIRONMENT_MANIFEST),
        "compiler environment manifest",
    )?;
    if bundles.schema_version != SYSTEM_PACKAGE_SCHEMA_VERSION
        || environment.schema_version != SYSTEM_PACKAGE_SCHEMA_VERSION
    {
        return Err(format!(
            "compiler package schema is incompatible; expected version {SYSTEM_PACKAGE_SCHEMA_VERSION}"
        ));
    }
    if bundles.coordinator_protocol_version != clusterflux_protocol::COORDINATOR_PROTOCOL_VERSION
        || bundles.wasm_task_abi_version != WASM_TASK_ABI_VERSION
    {
        return Err("compiler package protocol or Wasm ABI version is incompatible".to_owned());
    }
    let [bundle] = bundles.bundles.as_slice() else {
        return Err("system bundle manifest must contain exactly one compiler bundle".to_owned());
    };
    let release = workflow_compiler_system_manifest();
    if bundle.manifest != release {
        return Err(
            "system compiler bundle manifest does not match this Clusterflux release".to_owned(),
        );
    }
    if bundle.sdk_version != SUPPORTED_WORKFLOW_SDK_VERSION
        || bundle.serde_version != SUPPORTED_WORKFLOW_SERDE_VERSION
        || bundle.serde_features.as_slice() != ["derive"]
    {
        return Err("compiler package SDK or Serde identity is incompatible".to_owned());
    }
    if environment.environment_digest != release.environment_digest
        || environment.rust_toolchain != release.rust_toolchain
        || environment.sdk_version != SUPPORTED_WORKFLOW_SDK_VERSION
        || environment.sdk_digest != release.sdk_digest
        || environment.serde_version != SUPPORTED_WORKFLOW_SERDE_VERSION
        || environment.serde_features.as_slice() != ["derive"]
        || environment.supported_os != release.supported_os
        || environment.supported_arch != release.supported_arch
    {
        return Err(
            "compiler environment manifest does not match this Clusterflux release".to_owned(),
        );
    }
    if environment.supported_os != std::env::consts::OS
        || environment.supported_arch != std::env::consts::ARCH
    {
        return Err(format!(
            "compiler appliance supports {}/{} but this node is {}/{}",
            environment.supported_os,
            environment.supported_arch,
            std::env::consts::OS,
            std::env::consts::ARCH
        ));
    }
    if bundle.compiler_image_reference != environment.compiler_image_reference
        || bundle.compiler_image_digest != environment.compiler_image_digest
        || bundle.compiler_image_archive != environment.compiler_image_archive
        || bundle.compiler_image_archive_digest != environment.compiler_image_archive_digest
        || bundle.compiler_image_archive != SYSTEM_COMPILER_IMAGE_ARCHIVE
    {
        return Err("compiler image identities disagree between package manifests".to_owned());
    }
    let digest_file = fs::read_to_string(share_dir.join(COMPILER_IMAGE_DIGEST))
        .map_err(|error| format!("read compiler image digest: {error}"))?;
    if digest_file.trim() != environment.compiler_image_digest.as_str() {
        return Err("compiler image digest file disagrees with package manifests".to_owned());
    }
    let archive = share_dir.join(&environment.compiler_image_archive);
    Ok(VerifiedSystemCompilerPackage {
        share_dir: share_dir.to_owned(),
        archive,
        image_reference: environment.compiler_image_reference,
        image_digest: environment.compiler_image_digest,
        environment_digest: environment.environment_digest,
        archive_digest: environment.compiler_image_archive_digest,
    })
}

pub fn verify_system_compiler_package(
    share_dir: &Path,
) -> Result<VerifiedSystemCompilerPackage, String> {
    let package = inspect_system_compiler_package(share_dir)?;
    let actual_archive_digest = sha256_file(&package.archive)?;
    if actual_archive_digest != package.archive_digest {
        return Err(format!(
            "compiler image archive digest verification failed: expected {}, got {}",
            package.archive_digest, actual_archive_digest
        ));
    }
    Ok(package)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("read {label} at {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse {label} at {}: {error}", path.display()))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize {}: {error}", path.display()))?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

fn sha256_file(path: &Path) -> Result<Digest, String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("open compiler image archive at {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            format!("hash compiler image archive at {}: {error}", path.display())
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Digest::from_sha256_hex(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_manifest_detects_archive_corruption() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join(SYSTEM_COMPILER_IMAGE_ARCHIVE),
            b"image",
        )
        .unwrap();
        write_system_compiler_manifests(directory.path(), Digest::sha256("image-id")).unwrap();
        fs::write(
            directory.path().join(SYSTEM_COMPILER_IMAGE_ARCHIVE),
            b"corrupt",
        )
        .unwrap();
        let error = verify_system_compiler_package(directory.path()).unwrap_err();
        assert!(error.contains("archive digest"));
        assert!(error.contains("expected sha256:"));
        assert!(error.contains("got sha256:"));
    }

    #[test]
    fn metadata_inspection_does_not_read_the_compiler_archive() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join(SYSTEM_COMPILER_IMAGE_ARCHIVE);
        fs::write(&archive, b"image").unwrap();
        let expected =
            write_system_compiler_manifests(directory.path(), Digest::sha256("image-id")).unwrap();
        fs::remove_file(&archive).unwrap();
        assert_eq!(
            inspect_system_compiler_package(directory.path()).unwrap(),
            expected
        );
        assert!(verify_system_compiler_package(directory.path()).is_err());
    }

    #[test]
    fn metadata_inspection_rejects_a_mismatched_rust_toolchain() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join(SYSTEM_COMPILER_IMAGE_ARCHIVE),
            b"image",
        )
        .unwrap();
        write_system_compiler_manifests(directory.path(), Digest::sha256("image-id")).unwrap();
        let environment_path = directory.path().join(COMPILER_ENVIRONMENT_MANIFEST);
        let mut environment: InstalledCompilerEnvironmentManifest =
            read_json(&environment_path, "compiler environment manifest").unwrap();
        environment.rust_toolchain = "0.0.0-mismatch".to_owned();
        write_json(&environment_path, &environment).unwrap();

        let error = inspect_system_compiler_package(directory.path()).unwrap_err();
        assert!(error.contains("compiler environment manifest"));
        assert!(error.contains("does not match this Clusterflux release"));
    }
}
