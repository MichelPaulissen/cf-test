#!/bin/sh
set -eu

if [ "$#" -ne 7 ]; then
  echo "usage: build-release-assets.sh <commit> <ref> <archive> <deb> <rpm> <vsix> <installer>" >&2
  exit 2
fi

commit=$1
git_ref=$2
archive_output=$3
deb_output=$4
rpm_output=$5
vsix_output=$6
installer_output=$7

case "$commit" in
  ''|*[!0-9a-f]*) echo "invalid commit SHA" >&2; exit 1 ;;
esac
if [ "${#commit}" -ne 40 ]; then
  echo "invalid commit SHA" >&2
  exit 1
fi
test "$(git rev-parse HEAD)" = "$commit"
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64

package_version() {
  awk '
    /^\[package\]$/ { in_package=1; next }
    /^\[/ { in_package=0 }
    in_package && /^version[[:space:]]*=/ {
      value=$0
      sub(/^[^=]*=[[:space:]]*"/, "", value)
      sub(/"[[:space:]]*$/, "", value)
      print value
      exit
    }
  ' "$1"
}

version=$(package_version crates/clusterflux-cli/Cargo.toml)
test -n "$version"
for manifest in \
  crates/clusterflux-node/Cargo.toml \
  crates/clusterflux-coordinator/Cargo.toml \
  crates/clusterflux-relay/Cargo.toml \
  crates/clusterflux-dap/Cargo.toml
do
  test "$(package_version "$manifest")" = "$version"
done
vscode_version=$(node -p "require('./vscode-extension/package.json').version")
test "$vscode_version" = "$version"

short=$(printf '%s' "$commit" | cut -c1-12)
case "$git_ref" in
  refs/heads/main)
    release_tag="build-$short"
    package_release="0.git.$short"
    prerelease=true
    ;;
  "refs/tags/v$version")
    release_tag="v$version"
    package_release=1
    prerelease=false
    ;;
  *)
    echo "release assets require refs/heads/main or refs/tags/v$version" >&2
    exit 1
    ;;
esac

source_date_epoch=$(git show -s --format=%ct "$commit")
export SOURCE_DATE_EPOCH=$source_date_epoch

work=/tmp/clusterflux-release-assets
stage=$work/stage
assets=$work/assets
rm -rf "$work"
mkdir -p "$stage/bin" "$stage/share/clusterflux" "$stage/share/doc/clusterflux" "$assets"

cargo build --locked --release \
  -p clusterflux-cli \
  -p clusterflux-node \
  -p clusterflux-coordinator \
  -p clusterflux-relay \
  -p clusterflux-dap

target=${CARGO_TARGET_DIR:-target}/release
for binary in \
  clusterflux \
  clusterflux-node \
  clusterflux-environment-setup \
  clusterflux-coordinator \
  clusterflux-relay \
  clusterflux-debug-dap
do
  test -x "$target/$binary"
  install -m 0755 "$target/$binary" "$stage/bin/$binary"
done

system_package=${CLUSTERFLUX_SYSTEM_PACKAGE_DIR:-/clusterflux/system}
"$target/clusterflux-system-package" verify --share-dir "$system_package" >/dev/null
for name in \
  system-bundles.json \
  compiler-environment.json \
  compiler-image-digest.txt
do
  test -f "$system_package/$name"
  install -m 0644 "$system_package/$name" "$stage/share/clusterflux/$name"
done

# A large archive copy can fail transiently under a busy rootless container
# store. Only accept a byte-for-byte verified copy, and retry that copy in
# place rather than publishing a package with a rewritten digest.
archive_name=system-compiler-image.oci.tar
archive_copy_attempt=1
while [ "$archive_copy_attempt" -le 3 ]; do
  install -m 0644 "$system_package/$archive_name" "$stage/share/clusterflux/$archive_name"
  if "$target/clusterflux-system-package" verify --share-dir "$stage/share/clusterflux"; then
    break
  fi
  if [ "$archive_copy_attempt" -eq 3 ]; then
    echo "failed to stage a verified compiler image archive after 3 attempts" >&2
    exit 1
  fi
  echo "compiler image archive copy failed verification; retrying ($archive_copy_attempt/3)" >&2
  rm -f "$stage/share/clusterflux/$archive_name"
  archive_copy_attempt=$((archive_copy_attempt + 1))
done

install -m 0644 LICENSE-APACHE "$stage/share/doc/clusterflux/LICENSE-APACHE"
install -m 0644 LICENSE-MIT "$stage/share/doc/clusterflux/LICENSE-MIT"
cat > "$stage/share/doc/clusterflux/README-install.txt" <<EOF
Clusterflux $version for Linux x86-64.

The package includes the CLI, node, coordinator, relay, debugger adapter, and
the release-pinned automatic workflow compiler appliance.

Local .clusterflux compilation requires Cargo and the supported Rust target.
Container-backed task execution requires rootless Podman on the node.

Documentation: https://github.com/lesstuff/clusterflux
EOF

compiler_image_sha=$(sha256sum "$stage/share/clusterflux/system-compiler-image.oci.tar" | cut -d' ' -f1)
{
  printf '{\n'
  printf '  "format": "clusterflux-package-v1",\n'
  printf '  "version": "%s",\n' "$version"
  printf '  "commit": "%s",\n' "$commit"
  printf '  "release_tag": "%s",\n' "$release_tag"
  printf '  "architecture": "x86_64-linux",\n'
  printf '  "compiler_image_archive_sha256": "sha256:%s",\n' "$compiler_image_sha"
  printf '  "binaries": {\n'
  first=true
  for binary in "$stage"/bin/*; do
    name=$(basename "$binary")
    digest=$(sha256sum "$binary" | cut -d' ' -f1)
    if [ "$first" = true ]; then first=false; else printf ',\n'; fi
    printf '    "%s": "sha256:%s"' "$name" "$digest"
  done
  printf '\n  }\n'
  printf '}\n'
} > "$stage/share/clusterflux/package-manifest.json"

archive=$assets/clusterflux-linux-x86_64.tar.gz
(
  cd "$stage"
  tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -cf - .
) | gzip -n > "$archive"

export CLUSTERFLUX_STAGE_ROOT=$stage
export CLUSTERFLUX_PACKAGE_VERSION=$version
export CLUSTERFLUX_PACKAGE_RELEASE=$package_release
nfpm package --config packaging/nfpm.yaml --packager deb --target "$assets/clusterflux-linux-amd64.deb"
nfpm package --config packaging/nfpm.yaml --packager rpm --target "$assets/clusterflux-linux-x86_64.rpm"

rm -rf /tmp/clusterflux-vscode-build
cp -a vscode-extension /tmp/clusterflux-vscode-build
(
  cd /tmp/clusterflux-vscode-build
  npm ci --ignore-scripts --no-audit --no-fund
  npm run package:vsix -- --out "$assets/clusterflux-vscode.vsix"
)
test -s "$assets/clusterflux-vscode.vsix"

archive_sha=$(sha256sum "$archive" | cut -d' ' -f1)
deb_sha=$(sha256sum "$assets/clusterflux-linux-amd64.deb" | cut -d' ' -f1)
rpm_sha=$(sha256sum "$assets/clusterflux-linux-x86_64.rpm" | cut -d' ' -f1)

sed \
  -e "s|@RELEASE_TAG@|$release_tag|g" \
  -e "s|@VERSION@|$version|g" \
  -e "s|@ARCHIVE_SHA256@|$archive_sha|g" \
  -e "s|@DEB_SHA256@|$deb_sha|g" \
  -e "s|@RPM_SHA256@|$rpm_sha|g" \
  packaging/install.sh.in > "$assets/install.sh"
chmod 0755 "$assets/install.sh"

for name in \
  system-compiler-image.oci.tar \
  system-bundles.json \
  compiler-environment.json \
  compiler-image-digest.txt \
  package-manifest.json
do
  tar -tzf "$archive" | grep -F "./share/clusterflux/$name" >/dev/null
  dpkg-deb --contents "$assets/clusterflux-linux-amd64.deb" | grep -F "./usr/share/clusterflux/$name" >/dev/null
  rpm -qpl "$assets/clusterflux-linux-x86_64.rpm" | grep -F "/usr/share/clusterflux/$name" >/dev/null
done
dpkg-deb --info "$assets/clusterflux-linux-amd64.deb" >/dev/null
rpm -qpi "$assets/clusterflux-linux-x86_64.rpm" >/dev/null
sh -n "$assets/install.sh"
packaging/test-installer.sh "$assets"

install -m 0644 "$archive" "$archive_output"
install -m 0644 "$assets/clusterflux-linux-amd64.deb" "$deb_output"
install -m 0644 "$assets/clusterflux-linux-x86_64.rpm" "$rpm_output"
install -m 0644 "$assets/clusterflux-vscode.vsix" "$vsix_output"
install -m 0755 "$assets/install.sh" "$installer_output"
printf 'VERSION=%s\nTAG=%s\nPRERELEASE=%s\n' "$version" "$release_tag" "$prerelease"
