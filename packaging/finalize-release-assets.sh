#!/bin/sh
set -eu

if [ "$#" -ne 18 ]; then
  echo "usage: finalize-release-assets.sh <commit> <version> <tag> <source-snapshot> <windows-in> <archive-in> <deb-in> <rpm-in> <vsix-in> <installer-in> <archive-out> <deb-out> <rpm-out> <vsix-out> <installer-out> <windows-out> <windows-installer-out> <checksums-out>" >&2
  exit 2
fi

commit=$1
version=$2
tag=$3
source_snapshot=$4
windows_input=$5
archive_input=$6
deb_input=$7
rpm_input=$8
vsix_input=$9
linux_installer_input=${10}
archive_output=${11}
deb_output=${12}
rpm_output=${13}
vsix_output=${14}
linux_installer_output=${15}
windows_output=${16}
windows_installer_output=${17}
checksums_output=${18}

case "$commit" in ''|*[!0-9a-f]*) echo "invalid commit SHA" >&2; exit 1 ;; esac
test "${#commit}" -eq 40
case "$version" in ''|*[!0-9.]*) echo "invalid version" >&2; exit 1 ;; esac
case "$tag" in v"$version"|build-????????????) ;; *) echo "invalid release tag" >&2; exit 1 ;; esac
case "$source_snapshot" in sha256:*) ;; *) echo "invalid source snapshot" >&2; exit 1 ;; esac
snapshot_hex=${source_snapshot#sha256:}
case "$snapshot_hex" in ''|*[!0-9a-f]*) echo "invalid source snapshot" >&2; exit 1 ;; esac
test "${#snapshot_hex}" -eq 64

work=$(mktemp -d "${TMPDIR:-/tmp}/clusterflux-finalize.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
unzip -Z1 "$windows_input" | LC_ALL=C sort > "$work/windows-files"
cat > "$work/expected-windows-files" <<'EOF'
LICENSE-APACHE
LICENSE-MIT
README-install.txt
clusterflux-environment-setup.exe
clusterflux-node.exe
package-manifest.json
EOF
cmp "$work/expected-windows-files" "$work/windows-files"
unzip -q "$windows_input" -d "$work/windows"

manifest=$work/windows/package-manifest.json
jq -e \
  --arg version "$version" \
  --arg commit "$commit" \
  --arg snapshot "$source_snapshot" \
  '.format_version == 1
   and .kind == "clusterflux-windows-package"
   and .version == $version
   and .source_commit == $commit
   and .source_snapshot == $snapshot
   and .architecture == "x86_64-windows"
   and (.rust_toolchain | type == "string" and length > 0)' \
  "$manifest" >/dev/null

for name in clusterflux-environment-setup.exe clusterflux-node.exe; do
  actual="sha256:$(sha256sum "$work/windows/$name" | cut -d' ' -f1)"
  expected=$(jq -r --arg name "$name" '.binaries[$name] // empty' "$manifest")
  test "$actual" = "$expected"
done

install -m 0644 "$archive_input" "$archive_output"
install -m 0644 "$deb_input" "$deb_output"
install -m 0644 "$rpm_input" "$rpm_output"
install -m 0644 "$vsix_input" "$vsix_output"
install -m 0755 "$linux_installer_input" "$linux_installer_output"
install -m 0644 "$windows_input" "$windows_output"

windows_sha=$(sha256sum "$windows_output" | cut -d' ' -f1)
sed \
  -e "s|@RELEASE_TAG@|$tag|g" \
  -e "s|@VERSION@|$version|g" \
  -e "s|@WINDOWS_ARCHIVE_SHA256@|$windows_sha|g" \
  packaging/install-windows.ps1.in > "$windows_installer_output"
chmod 0644 "$windows_installer_output"
if grep -F '@RELEASE_TAG@' "$windows_installer_output" >/dev/null ||
   grep -F '@VERSION@' "$windows_installer_output" >/dev/null ||
   grep -F '@WINDOWS_ARCHIVE_SHA256@' "$windows_installer_output" >/dev/null
then
  echo "Windows installer still contains template placeholders" >&2
  exit 1
fi

output_dir=$(dirname "$checksums_output")
test "$output_dir" = "$(dirname "$archive_output")"
(
  cd "$output_dir"
  sha256sum \
    clusterflux-linux-x86_64.tar.gz \
    clusterflux-linux-amd64.deb \
    clusterflux-linux-x86_64.rpm \
    clusterflux-windows-x86_64.zip \
    clusterflux-vscode.vsix \
    install.sh \
    install-windows.ps1 \
    > SHA256SUMS
)
test "$checksums_output" = "$output_dir/SHA256SUMS"
