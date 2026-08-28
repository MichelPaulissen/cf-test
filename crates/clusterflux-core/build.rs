use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

const INPUT_ROOTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "compiler-toolchain.json",
    "crates/clusterflux-core/Cargo.toml",
    "crates/clusterflux-core/build.rs",
    "crates/clusterflux-core/src",
    "crates/clusterflux-macros",
    "crates/clusterflux-sdk",
    "system-bundles/workflow-compiler/driver",
    "system-bundles/workflow-compiler/envs/compiler",
    "system-bundles/workflow-compiler/package.js",
];

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let repository = manifest.parent().unwrap().parent().unwrap();
    let toolchain: serde_json::Value = serde_json::from_slice(
        &fs::read(repository.join("compiler-toolchain.json"))
            .expect("read compiler-toolchain.json"),
    )
    .expect("parse compiler-toolchain.json");
    let rust_release = toolchain["rust_release"]
        .as_str()
        .expect("compiler toolchain rust_release is a string");
    let wasm_target = toolchain["wasm_target"]
        .as_str()
        .expect("compiler toolchain wasm_target is a string");
    println!("cargo:rustc-env=CLUSTERFLUX_COMPILER_RUST_RELEASE={rust_release}");
    println!("cargo:rustc-env=CLUSTERFLUX_COMPILER_WASM_TARGET={wasm_target}");
    let mut files = Vec::new();
    for input in INPUT_ROOTS {
        collect_files(&repository.join(input), &mut files);
    }
    files.sort();
    files.dedup();

    let mut hasher = Sha256::new();
    hash_part(&mut hasher, b"clusterflux-system-compiler-environment:v2");
    for file in files {
        println!("cargo:rerun-if-changed={}", file.display());
        let relative = file.strip_prefix(repository).unwrap();
        hash_part(
            &mut hasher,
            relative.to_string_lossy().replace('\\', "/").as_bytes(),
        );
        hash_part(&mut hasher, &fs::read(&file).unwrap());
    }
    println!(
        "cargo:rustc-env=CLUSTERFLUX_COMPILER_ENVIRONMENT_INPUT_DIGEST={:x}",
        hasher.finalize()
    );
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_file() {
        files.push(path.to_owned());
        return;
    }
    let mut entries = fs::read_dir(path)
        .unwrap_or_else(|error| {
            panic!(
                "read compiler environment input {}: {error}",
                path.display()
            )
        })
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    entries.sort();
    for entry in entries {
        if entry.is_dir() {
            collect_files(&entry, files);
        } else if entry.is_file() {
            files.push(entry);
        }
    }
}

fn hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}
