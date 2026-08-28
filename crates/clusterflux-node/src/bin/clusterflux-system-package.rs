use std::path::PathBuf;

use clap::{Parser, Subcommand};
use clusterflux_core::Digest;
use clusterflux_node::system_package::{
    verify_system_compiler_package, write_system_compiler_manifests,
};

#[derive(Parser)]
#[command(name = "clusterflux-system-package", version)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Write {
        #[arg(long)]
        share_dir: PathBuf,
        #[arg(long)]
        image_digest: String,
    },
    Verify {
        #[arg(long)]
        share_dir: PathBuf,
    },
}

fn main() -> Result<(), String> {
    let package = match Args::parse().command {
        Command::Write {
            share_dir,
            image_digest,
        } => write_system_compiler_manifests(
            &share_dir,
            Digest::from_sha256_hex(
                image_digest
                    .strip_prefix("sha256:")
                    .ok_or("--image-digest must begin with sha256:")?,
            )?,
        )?,
        Command::Verify { share_dir } => verify_system_compiler_package(&share_dir)?,
    };
    println!(
        "{}",
        serde_json::json!({
            "share_dir": package.share_dir,
            "archive": package.archive,
            "image_reference": package.image_reference,
            "image_digest": package.image_digest,
            "environment_digest": package.environment_digest,
        })
    );
    Ok(())
}
