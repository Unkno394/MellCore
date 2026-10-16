#!/bin/sh
set -eu

host=${1:?usage: verify-high-ssh.sh HOST PORT USERNAME}
port=${2:?usage: verify-high-ssh.sh HOST PORT USERNAME}
username=${3:?usage: verify-high-ssh.sh HOST PORT USERNAME}

case "$host" in
  ''|-*|*[!A-Za-z0-9:._%-]*) echo 'invalid SSH host argument' >&2; exit 2 ;;
esac
case "$port" in
  ''|*[!0-9]*) echo 'SSH port must be numeric' >&2; exit 2 ;;
esac
[ "${#port}" -le 5 ] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || {
  echo 'SSH port must be in 1..65535' >&2
  exit 2
}
case "$username" in
  ''|-*|*[!A-Za-z0-9_.-]*) echo 'invalid SSH username argument' >&2; exit 2 ;;
esac

output=$(ssh \
  -p "$port" \
  -o ConnectTimeout=10 \
  -o ConnectionAttempts=1 \
  -o ServerAliveInterval=5 \
  -o ServerAliveCountMax=2 \
  -o PreferredAuthentications=password,keyboard-interactive \
  -o PubkeyAuthentication=no \
  "$username@$host" \
  'printf "HF_HIGH_E2E_OK\\n"; id; uname -s')
printf '%s\n' "$output"
case "$output" in
  *HF_HIGH_E2E_OK*) ;;
  *) echo 'SSH connected, but the remote command did not return its success marker' >&2; exit 1 ;;
esac
