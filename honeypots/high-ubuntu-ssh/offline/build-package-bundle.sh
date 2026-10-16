#!/bin/sh
set -eu

output_dir=${1:?usage: build-package-bundle.sh OUTPUT_DIRECTORY}
for command in dpkg-deb sha256sum; do command -v "$command" >/dev/null; done

validate_bundle() {
  directory=$1
  [ -s "$directory/SHA256SUMS" ] && [ -s "$directory/VERSIONS" ] || return 1
  set -- "$directory"/*.deb
  [ -f "$1" ] || return 1
  (cd "$directory" && sha256sum -c SHA256SUMS >/dev/null) || return 1
  for package in "$@"; do dpkg-deb --info "$package" >/dev/null 2>&1 || return 1; done
  grep -qx 'ubuntu_release=24.04' "$directory/VERSIONS" || return 1
  grep -qx 'architecture=amd64' "$directory/VERSIONS" || return 1
}

if [ -d "$output_dir" ] && validate_bundle "$output_dir"; then
  printf '%s\n' "verified cached Ubuntu offline package bundle: $output_dir"
  exit 0
fi
[ ! -e "$output_dir" ] || {
  echo "HF_HIGH_ERROR code=OFFLINE_BUNDLE_INVALID stage=installation: cached Ubuntu offline package bundle failed integrity validation: $output_dir" >&2
  exit 1
}
for command in apt-get dpkg; do command -v "$command" >/dev/null; done
[ "$(dpkg --print-architecture)" = amd64 ] || {
  echo 'HF_HIGH_ERROR code=OFFLINE_BUNDLE_ARCH_UNSUPPORTED stage=installation: Ubuntu offline packages require an amd64 host' >&2
  exit 1
}
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
[ -r "$keyring" ] || {
  echo "HF_HIGH_ERROR code=OFFLINE_BUNDLE_TRUST_MISSING stage=installation: trusted Ubuntu archive keyring is unavailable at $keyring" >&2
  exit 1
}

parent_dir=$(dirname "$output_dir")
mkdir -p "$parent_dir"
parent_dir=$(CDPATH= cd -- "$parent_dir" && pwd)
output_dir="$parent_dir/$(basename "$output_dir")"
lock_dir="$output_dir.lock"
attempt=0
while ! mkdir "$lock_dir" 2>/dev/null; do
  if [ -r "$lock_dir/pid" ]; then
    owner=$(cat "$lock_dir/pid" 2>/dev/null || true)
    case "$owner" in
      ''|*[!0-9]*) ;;
      *)
        if ! kill -0 "$owner" 2>/dev/null && [ "$(cat "$lock_dir/pid" 2>/dev/null || true)" = "$owner" ]; then
          rm -rf "$lock_dir"
          continue
        fi
        ;;
    esac
  fi
  attempt=$((attempt + 1))
  [ "$attempt" -le 120 ] || {
    echo "HF_HIGH_ERROR code=OFFLINE_BUNDLE_LOCK_TIMEOUT stage=installation: timed out waiting for $lock_dir" >&2
    exit 1
  }
  sleep 1
  if [ -d "$output_dir" ] && validate_bundle "$output_dir"; then exit 0; fi
done
printf '%s\n' "$$" > "$lock_dir/pid"
work_dir=$(mktemp -d "$parent_dir/.ubuntu-offline.XXXXXX")
cleanup() { rm -rf "$work_dir" "$lock_dir"; }
trap cleanup EXIT HUP INT TERM

mkdir -p "$work_dir/apt/lists/partial" "$work_dir/apt/archives/partial" "$work_dir/bundle"
: > "$work_dir/apt/status"
cat > "$work_dir/apt/sources.list" <<EOF
deb [arch=amd64 signed-by=$keyring] https://archive.ubuntu.com/ubuntu noble main universe
deb [arch=amd64 signed-by=$keyring] https://archive.ubuntu.com/ubuntu noble-updates main universe
deb [arch=amd64 signed-by=$keyring] https://security.ubuntu.com/ubuntu noble-security main universe
EOF
apt_target() {
  apt-get \
    -o "Dir::Etc::sourcelist=$work_dir/apt/sources.list" \
    -o Dir::Etc::sourceparts=- \
    -o "Dir::State::status=$work_dir/apt/status" \
    -o "Dir::State::lists=$work_dir/apt/lists" \
    -o "Dir::Cache::archives=$work_dir/apt/archives" \
    -o APT::Architecture=amd64 \
    -o Acquire::Languages=none \
    "$@"
}

# APT authenticates Release metadata and package hashes with Ubuntu's archive keyring.  Packages
# are downloaded by the host, never by the isolated guest.
apt_target update
apt_target --download-only -y --no-install-recommends install \
  auditd audispd-plugins qemu-guest-agent
cp "$work_dir"/apt/archives/*.deb "$work_dir/bundle/"
set -- "$work_dir/bundle"/*.deb
[ -f "$1" ] || {
  echo 'HF_HIGH_ERROR code=OFFLINE_BUNDLE_EMPTY stage=installation: APT produced no Ubuntu packages' >&2
  exit 1
}
for package in "$@"; do
  dpkg-deb --info "$package" >/dev/null
  architecture=$(dpkg-deb -f "$package" Architecture)
  case "$architecture" in amd64|all) ;; *)
    echo "HF_HIGH_ERROR code=OFFLINE_BUNDLE_ARCH_MISMATCH stage=installation: $(basename "$package") has architecture $architecture" >&2
    exit 1
  esac
done
(
  cd "$work_dir/bundle"
  sha256sum ./*.deb | sed 's#  \./#  #' > SHA256SUMS
  {
    printf '%s\n' 'ubuntu_release=24.04' 'architecture=amd64'
    for package in ./*.deb; do dpkg-deb -f "$package" Package Version | tr '\n' ' '; printf '\n'; done
  } > VERSIONS
)
validate_bundle "$work_dir/bundle" || {
  echo 'HF_HIGH_ERROR code=OFFLINE_BUNDLE_VERIFY_FAILED stage=installation: generated Ubuntu package bundle failed validation' >&2
  exit 1
}
mv "$work_dir/bundle" "$output_dir"
printf '%s\n' "offline package bundle created in $output_dir"
