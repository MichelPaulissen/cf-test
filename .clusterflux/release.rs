use std::time::Duration;

use clusterflux::prelude::*;
use clusterflux::serde::{Deserialize, Serialize};

use crate::tasks::{
    ARCHIVE_NAME, CHECKSUMS_NAME, DEB_NAME, INSTALLER_NAME, RPM_NAME, ReleaseAssets, VSIX_NAME,
    WINDOWS_ARCHIVE_NAME, WINDOWS_INSTALLER_NAME,
};

#[derive(Clone, Serialize, Deserialize, clusterflux::TaskArg)]
#[serde(crate = "clusterflux::serde")]
pub struct PublishInput {
    pub repository_id: String,
    pub commit_sha: String,
    pub git_ref: String,
    pub trusted: bool,
    pub assets: ReleaseAssets,
}

#[derive(Clone, Serialize, Deserialize, clusterflux::TaskArg)]
#[serde(crate = "clusterflux::serde")]
pub struct NixCachePublication {
    pub attempted: bool,
    pub succeeded: bool,
    pub failure: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, clusterflux::TaskArg)]
#[serde(crate = "clusterflux::serde")]
pub struct PublicationResult {
    pub tag: String,
    pub release_url: String,
    pub uploaded_asset_names: Vec<String>,
    pub published_at: u64,
    pub nix_cache: NixCachePublication,
}

#[clusterflux::task(capabilities = "command,network,secrets,vfs_artifacts")]
pub async fn publish(input: PublishInput) -> Result<PublicationResult> {
    if !input.trusted {
        return Err(clusterflux::Error::Argument(
            "publication requires a trusted trigger".to_owned(),
        ));
    }

    let repository = input
        .repository_id
        .strip_prefix("github:")
        .filter(|value| value.split('/').count() == 2)
        .ok_or_else(|| {
            clusterflux::Error::Argument(
                "publication trigger is not a configured GitHub repository".to_owned(),
            )
        })?;

    validate_release_identity(&input)?;

    let archive = fs::materialize(&input.assets.archive, ARCHIVE_NAME).await?;
    let deb = fs::materialize(&input.assets.deb, DEB_NAME).await?;
    let rpm = fs::materialize(&input.assets.rpm, RPM_NAME).await?;
    let vscode = fs::materialize(&input.assets.vscode, VSIX_NAME).await?;
    let installer = fs::materialize(&input.assets.installer, INSTALLER_NAME).await?;
    let windows_archive =
        fs::materialize(&input.assets.windows_archive, WINDOWS_ARCHIVE_NAME).await?;
    let windows_installer =
        fs::materialize(&input.assets.windows_installer, WINDOWS_INSTALLER_NAME).await?;
    let checksums = fs::materialize(&input.assets.checksums, CHECKSUMS_NAME).await?;

    let title = if input.assets.prerelease {
        format!("Clusterflux build {}", short_sha(&input.commit_sha)?)
    } else {
        format!("Clusterflux {}", input.assets.tag)
    };

    let args = vec![
        "-eu".to_owned(),
        "-c".to_owned(),
        PUBLISH_SCRIPT.to_owned(),
        "clusterflux-publish".to_owned(),
        repository.to_owned(),
        input.commit_sha.clone(),
        input.assets.tag.clone(),
        title,
        input.assets.prerelease.to_string(),
        ARCHIVE_NAME.to_owned(),
        archive.as_str().to_owned(),
        input.assets.archive.digest.clone(),
        input.assets.archive.size_bytes.to_string(),
        DEB_NAME.to_owned(),
        deb.as_str().to_owned(),
        input.assets.deb.digest.clone(),
        input.assets.deb.size_bytes.to_string(),
        RPM_NAME.to_owned(),
        rpm.as_str().to_owned(),
        input.assets.rpm.digest.clone(),
        input.assets.rpm.size_bytes.to_string(),
        VSIX_NAME.to_owned(),
        vscode.as_str().to_owned(),
        input.assets.vscode.digest.clone(),
        input.assets.vscode.size_bytes.to_string(),
        INSTALLER_NAME.to_owned(),
        installer.as_str().to_owned(),
        input.assets.installer.digest.clone(),
        input.assets.installer.size_bytes.to_string(),
        WINDOWS_ARCHIVE_NAME.to_owned(),
        windows_archive.as_str().to_owned(),
        input.assets.windows_archive.digest.clone(),
        input.assets.windows_archive.size_bytes.to_string(),
        WINDOWS_INSTALLER_NAME.to_owned(),
        windows_installer.as_str().to_owned(),
        input.assets.windows_installer.digest.clone(),
        input.assets.windows_installer.size_bytes.to_string(),
        CHECKSUMS_NAME.to_owned(),
        checksums.as_str().to_owned(),
        input.assets.checksums.digest.clone(),
        input.assets.checksums.size_bytes.to_string(),
    ];

    let output = Command::new("sh")
        .args(args)
        .secret_env("GH_TOKEN", "github-release")
        .network_enabled()
        .timeout(Duration::from_secs(20 * 60))
        .run()
        .await?;

    let result = parse_result(&output.stdout)?;
    input.assets.archive.release().await?;
    input.assets.deb.release().await?;
    input.assets.rpm.release().await?;
    input.assets.vscode.release().await?;
    input.assets.installer.release().await?;
    input.assets.windows_archive.release().await?;
    input.assets.windows_installer.release().await?;
    input.assets.checksums.release().await?;
    Ok(result)
}

fn validate_release_identity(input: &PublishInput) -> Result<()> {
    let expected_tag = if input.git_ref == "refs/heads/main" {
        format!("build-{}", short_sha(&input.commit_sha)?)
    } else if let Some(version) = input.git_ref.strip_prefix("refs/tags/v") {
        if version != input.assets.version {
            return Err(clusterflux::Error::Argument(
                "release tag does not match package version".to_owned(),
            ));
        }
        format!("v{version}")
    } else {
        return Err(clusterflux::Error::Argument(
            "publication requires trusted main or an exact version tag".to_owned(),
        ));
    };

    let expected_prerelease = input.git_ref == "refs/heads/main";
    if input.assets.tag != expected_tag || input.assets.prerelease != expected_prerelease {
        return Err(clusterflux::Error::Argument(
            "release assets do not match the trigger release identity".to_owned(),
        ));
    }
    Ok(())
}

fn short_sha(commit_sha: &str) -> Result<&str> {
    if commit_sha.len() != 40
        || !commit_sha
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(clusterflux::Error::Argument(
            "trigger commit SHA is malformed".to_owned(),
        ));
    }
    Ok(&commit_sha[..12])
}

fn parse_result(stdout: &str) -> Result<PublicationResult> {
    let field = |name: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                clusterflux::Error::Protocol(format!(
                    "GitHub publication omitted result field {name}"
                ))
            })
    };

    let tag = field("TAG=")?;
    let release_url = field("URL=")?;
    let published_at = field("PUBLISHED_AT=")?
        .parse::<u64>()
        .map_err(|_| clusterflux::Error::Protocol("invalid publication timestamp".to_owned()))?;

    Ok(PublicationResult {
        tag,
        release_url,
        uploaded_asset_names: vec![
            ARCHIVE_NAME.to_owned(),
            DEB_NAME.to_owned(),
            RPM_NAME.to_owned(),
            VSIX_NAME.to_owned(),
            INSTALLER_NAME.to_owned(),
            WINDOWS_ARCHIVE_NAME.to_owned(),
            WINDOWS_INSTALLER_NAME.to_owned(),
            CHECKSUMS_NAME.to_owned(),
        ],
        published_at,
        nix_cache: NixCachePublication {
            attempted: false,
            succeeded: false,
            failure: None,
        },
    })
}

const PUBLISH_SCRIPT: &str = r#"
repo="$1"
sha="$2"
tag="$3"
title="$4"
prerelease="$5"
shift 5

expected="/tmp/clusterflux-release-assets.$$"
verification_dir="/tmp/clusterflux-release-verification.$$"
trap 'rm -rf "$expected" "$verification_dir"' EXIT HUP INT TERM
: > "$expected"
mkdir -p "$verification_dir"

if ! gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
  if [ "$prerelease" = true ]; then
    gh release create "$tag" --repo "$repo" --target "$sha" --title "$title" --draft --prerelease
  else
    gh release create "$tag" --repo "$repo" --target "$sha" --title "$title" --draft
  fi
fi

release_json="$(gh release view "$tag" --repo "$repo" --json targetCommitish,isDraft,isPrerelease,url)"
target="$(printf '%s' "$release_json" | jq -r .targetCommitish)"
remote_prerelease="$(printf '%s' "$release_json" | jq -r .isPrerelease)"
is_draft="$(printf '%s' "$release_json" | jq -r .isDraft)"

test "$target" = "$sha"
test "$remote_prerelease" = "$prerelease"

verify_or_upload() {
  name="$1"
  file="$2"
  expected_digest="$3"
  expected_size="$4"
  printf '%s\n' "$name" >> "$expected"

  actual_digest="sha256:$(sha256sum "$file" | cut -d' ' -f1)"
  actual_size="$(wc -c < "$file" | tr -d ' ')"
  test "$actual_digest" = "$expected_digest"
  test "$actual_size" = "$expected_size"

  if line="$(gh release view "$tag" --repo "$repo" --json assets --jq '.assets[] | [.name, .size, (.digest // "")] | @tsv' | awk -F '\t' -v wanted="$name" '$1 == wanted { print; found=1 } END { if (!found) exit 1 }')"; then
    remote_size="$(printf '%s' "$line" | cut -f2)"
    remote_digest="$(printf '%s' "$line" | cut -f3)"
    test "$remote_size" = "$expected_size"
    if [ -n "$remote_digest" ]; then
      test "$remote_digest" = "$expected_digest"
    else
      rm -f "$verification_dir/$name"
      gh release download "$tag" --repo "$repo" --pattern "$name" --dir "$verification_dir" --clobber
      downloaded_digest="sha256:$(sha256sum "$verification_dir/$name" | cut -d' ' -f1)"
      test "$downloaded_digest" = "$expected_digest"
    fi
  else
    gh release upload "$tag" "$file#$name" --repo "$repo"
  fi
}

while [ "$#" -gt 0 ]; do
  test "$#" -ge 4
  verify_or_upload "$1" "$2" "$3" "$4"
  shift 4
done

remote_names="$(gh release view "$tag" --repo "$repo" --json assets --jq '.assets[].name' | sort)"
expected_names="$(sort "$expected")"
test "$remote_names" = "$expected_names"

if [ "$is_draft" = true ]; then
  if [ "$prerelease" = true ]; then
    gh release edit "$tag" --repo "$repo" --draft=false --prerelease
  else
    gh release edit "$tag" --repo "$repo" --draft=false
  fi
fi

url="$(gh release view "$tag" --repo "$repo" --json url --jq .url)"
printf 'TAG=%s\nURL=%s\nPUBLISHED_AT=%s\n' "$tag" "$url" "$(date +%s)"
"#;
