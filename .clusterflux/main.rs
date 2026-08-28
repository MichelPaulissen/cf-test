mod release;
mod tasks;
mod windows;

use clusterflux::prelude::*;
use release::{PublicationResult, PublishInput, publish};
use tasks::{
    BuildReleaseInput, CacheNixInput, FinalizeReleaseInput, PRODUCT_VERSION, TestInput,
    build_linux_release_assets, cache_nix_package, finalize_release_assets, test_public_repo,
};
use windows::{WindowsReleaseInput, build_windows_release_package};

#[clusterflux::main]
pub async fn main() -> Result<Option<PublicationResult>> {
    let trigger = trigger::current().await?;
    let source = trigger.source.clone();

    clusterflux::spawn!(test_public_repo(TestInput {
        source: source.clone(),
        commit_sha: trigger.commit_sha.clone(),
    }))
    .on(clusterflux::env!("release-build"))
    .await?
    .join()
    .await?;

    // Non-release refs still get the full test gate, but never receive the
    // publication secret or spend node time building distributable packages.
    if !trigger.trusted || !publishable_ref(&trigger.git_ref) {
        return Ok(None);
    }

    let linux = clusterflux::spawn!(build_linux_release_assets(BuildReleaseInput {
        source: source.clone(),
        commit_sha: trigger.commit_sha.clone(),
        git_ref: trigger.git_ref.clone(),
    }))
    .on(clusterflux::env!("release-build"))
    .await?;
    let windows = clusterflux::spawn!(build_windows_release_package(WindowsReleaseInput {
        source: source.clone(),
        commit_sha: trigger.commit_sha.clone(),
        version: PRODUCT_VERSION.to_owned(),
    }))
    .on(clusterflux::env!("windows-node-build"))
    .await?;

    let linux = linux.join().await?;
    let windows = windows.join().await?;
    let assets = clusterflux::spawn!(finalize_release_assets(FinalizeReleaseInput {
        source: source.clone(),
        commit_sha: trigger.commit_sha.clone(),
        linux,
        windows,
    }))
    .on(clusterflux::env!("release-build"))
    .await?
    .join()
    .await?;

    let cache_publication = if stable_release_ref(&trigger.git_ref) {
        Some(
            clusterflux::spawn!(cache_nix_package(CacheNixInput {
                source,
                commit_sha: trigger.commit_sha.clone(),
                tag: assets.tag.clone(),
            }))
            .on(clusterflux::env!("nix-cache-publish"))
            .secret("cachix-auth-token")
            .await,
        )
    } else {
        None
    };

    let mut publication = clusterflux::spawn!(publish(PublishInput {
        repository_id: trigger.repository_id,
        commit_sha: trigger.commit_sha,
        git_ref: trigger.git_ref,
        trusted: trigger.trusted,
        assets,
    }))
    .on(clusterflux::env!("github-publish"))
    .secret("github-release")
    .await?
    .join()
    .await?;

    publication.nix_cache = match cache_publication {
        None => release::NixCachePublication {
            attempted: false,
            succeeded: false,
            failure: None,
        },
        Some(Ok(task)) => match task.join().await {
            Ok(()) => release::NixCachePublication {
                attempted: true,
                succeeded: true,
                failure: None,
            },
            Err(error) => release::NixCachePublication {
                attempted: true,
                succeeded: false,
                failure: Some(error.to_string()),
            },
        },
        Some(Err(error)) => release::NixCachePublication {
            attempted: true,
            succeeded: false,
            failure: Some(error.to_string()),
        },
    };

    Ok(Some(publication))
}

fn publishable_ref(git_ref: &str) -> bool {
    git_ref == "refs/heads/main" || stable_release_ref(git_ref)
}

fn stable_release_ref(git_ref: &str) -> bool {
    git_ref
        .strip_prefix("refs/tags/v")
        .is_some_and(is_semver_core)
}

fn is_semver_core(value: &str) -> bool {
    let mut parts = value.split('.');
    let valid = (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    });
    valid && parts.next().is_none()
}
