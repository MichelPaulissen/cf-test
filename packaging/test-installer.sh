#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: test-installer.sh <release-assets-directory>" >&2
  exit 2
fi

assets=$(cd "$1" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/clusterflux-installer-test.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir -p "$work/bin" "$work/home" "$work/prefix"
real_uid=$(id -u)

cat > "$work/bin/curl" <<'EOF'
#!/bin/sh
set -eu
url=
output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output=$2; shift 2 ;;
    http://*|https://*) url=$1; shift ;;
    *) shift ;;
  esac
done
test -n "$url"
test -n "$output"
cp "$CLUSTERFLUX_TEST_ASSETS/${url##*/}" "$output"
EOF
chmod 0755 "$work/bin/curl"

cat > "$work/bin/id" <<'EOF'
#!/bin/sh
test "${1:-}" = -u
printf '1000\n'
EOF
chmod 0755 "$work/bin/id"

PATH="$work/bin:$PATH" \
HOME="$work/home" \
CLUSTERFLUX_TEST_ASSETS="$assets" \
  sh "$assets/install.sh" >"$work/non-root-output"

# A non-root automatic install selects the archive and the default user prefix.
test -x "$work/home/.local/bin/clusterflux"
grep -F "Add $work/home/.local/bin to PATH" "$work/non-root-output" >/dev/null

# Reinstalling an identical user release is intentionally safe and idempotent.
PATH="$work/bin:$PATH" \
HOME="$work/home" \
CLUSTERFLUX_TEST_ASSETS="$assets" \
  sh "$assets/install.sh" >/dev/null

for name in \
  system-compiler-image.oci.tar \
  system-bundles.json \
  compiler-environment.json \
  compiler-image-digest.txt \
  package-manifest.json
do
  test -s "$work/home/.local/share/clusterflux/$name"
done

broken=$work/install-bad-checksum.sh
sed "s/^archive_sha256=.*/archive_sha256='0000000000000000000000000000000000000000000000000000000000000000'/" \
  "$assets/install.sh" > "$broken"
if PATH="$work/bin:$PATH" \
  HOME="$work/home" \
  CLUSTERFLUX_TEST_ASSETS="$assets" \
  CLUSTERFLUX_INSTALL_METHOD=archive \
  CLUSTERFLUX_INSTALL_PREFIX="$work/bad-prefix" \
  sh "$broken" >/dev/null 2>&1
then
  echo "installer accepted a checksum mismatch" >&2
  exit 1
fi

cat > "$work/bin/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -s) printf 'Linux\n' ;;
  -m) printf 'aarch64\n' ;;
  *) printf 'Linux\n' ;;
esac
EOF
chmod 0755 "$work/bin/uname"
if PATH="$work/bin:$PATH" HOME="$work/home" sh "$assets/install.sh" >/dev/null 2>&1; then
  echo "installer accepted an unsupported architecture" >&2
  exit 1
fi

# The release-build container runs as root inside a rootless user namespace.
# Package contents and metadata are checked separately; exercise the installer's
# root package-manager selection here without requiring privileged setuid calls.
if [ "$real_uid" -eq 0 ]; then
  mkdir -p "$work/root-deb-bin"
  cp "$work/bin/curl" "$work/root-deb-bin/curl"
  cat > "$work/root-deb-bin/apt-get" <<'EOF'
#!/bin/sh
set -eu
test "$#" -eq 3
test "$1" = install
test "$2" = -y
test -s "$3"
sha256sum "$3" | cut -d' ' -f1 > "$CLUSTERFLUX_TEST_APT_RECORD"
EOF
  chmod 0755 "$work/root-deb-bin/apt-get"
  PATH="$work/root-deb-bin:$PATH" \
  HOME="$work/home" \
  CLUSTERFLUX_TEST_ASSETS="$assets" \
  CLUSTERFLUX_TEST_APT_RECORD="$work/apt-package.sha256" \
    sh "$assets/install.sh" >/dev/null
  test "$(cat "$work/apt-package.sha256")" = \
    "$(sha256sum "$assets/clusterflux-linux-amd64.deb" | cut -d' ' -f1)"

  mkdir -p "$work/root-rpm-bin"
  cp "$work/bin/curl" "$work/root-rpm-bin/curl"
  for command in cp cut id mktemp rm sh sha256sum uname; do
    ln -s "$(command -v "$command")" "$work/root-rpm-bin/$command"
  done
  cat > "$work/root-rpm-bin/rpm" <<'EOF'
#!/bin/sh
set -eu
test "$#" -eq 3
test "$1" = -Uvh
test "$2" = --replacepkgs
test -s "$3"
sha256sum "$3" | cut -d' ' -f1 > "$CLUSTERFLUX_TEST_RPM_RECORD"
EOF
  chmod 0755 "$work/root-rpm-bin/rpm"
  PATH="$work/root-rpm-bin" \
  HOME="$work/home" \
  CLUSTERFLUX_TEST_ASSETS="$assets" \
  CLUSTERFLUX_TEST_RPM_RECORD="$work/rpm-package.sha256" \
    sh "$assets/install.sh" >/dev/null
  test "$(cat "$work/rpm-package.sha256")" = \
    "$(sha256sum "$assets/clusterflux-linux-x86_64.rpm" | cut -d' ' -f1)"

  mkdir -p "$work/root-archive-bin" "$work/root-prefix"
  cp "$work/bin/curl" "$work/root-archive-bin/curl"
  for command in cp cut gzip id mkdir mktemp rm sh sha256sum tar uname; do
    ln -s "$(command -v "$command")" "$work/root-archive-bin/$command"
  done
  PATH="$work/root-archive-bin" \
  HOME="$work/home" \
  CLUSTERFLUX_TEST_ASSETS="$assets" \
  CLUSTERFLUX_INSTALL_PREFIX="$work/root-prefix" \
    sh "$assets/install.sh" >/dev/null
  test -x "$work/root-prefix/bin/clusterflux"
  test -s "$work/root-prefix/share/clusterflux/system-compiler-image.oci.tar"
fi
