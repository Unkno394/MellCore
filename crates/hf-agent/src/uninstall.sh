#!/bin/sh
set -eu

requested_state_dir=${1:-/var/lib/honeyforge}
expected_agent_id=${2:-}
state_dir=$(readlink -f -- "$requested_state_dir") || {
  echo "Cannot resolve agent state directory" >&2
  exit 1
}
if [ "$state_dir" != "$requested_state_dir" ]; then
  echo "Refusing non-canonical agent state directory: $requested_state_dir" >&2
  exit 1
fi
case "$state_dir" in
  /var/lib/honeyforge) shared_state=1 ;;
  /var/lib/honeyforge/*) shared_state=0 ;;
  *)
    echo "Refusing to remove unsafe agent state directory: $state_dir" >&2
    exit 1
    ;;
esac

# A scheduled uninstall may fire after a new agent has been enrolled. Never
# remove the replacement agent or its service in that case.
if [ -n "$expected_agent_id" ]; then
  identity_file="$state_dir/identity.json"
  if [ ! -f "$identity_file" ] || ! grep -Eq '"agent_id"[[:space:]]*:[[:space:]]*"'"$expected_agent_id"'"' "$identity_file"; then
    echo "Agent identity changed since uninstall was scheduled; leaving current installation intact" >&2
    rm -f "$0"
    exit 0
  fi
fi

systemctl disable --now \
  hf-agent.service hf-hysteria-client.service hf-dispatcher.service \
  honeyforge-emergency.service 2>/dev/null || true
rm -f \
  /etc/systemd/system/hf-agent.service \
  /etc/systemd/system/hf-hysteria-client.service \
  /etc/systemd/system/hf-dispatcher.service \
  /etc/systemd/system/honeyforge-emergency.service
systemctl daemon-reload

# Center and backend can share these parent directories and the Hysteria binary.
rm -f /usr/local/bin/hf-agent /usr/local/bin/hf-dispatcher \
  /usr/local/libexec/honeyforge-emergency
rm -f /etc/honeyforge/enrollment-token \
  /etc/honeyforge/agent.env /etc/honeyforge/hysteria-client.yaml \
  /etc/honeyforge/dispatcher.json
if [ "$shared_state" -eq 1 ]; then
  # Keep the historical selective cleanup for the shared default directory.
  rm -rf -- "$state_dir/traps" "$state_dir/high" \
    "$state_dir/inbox" "$state_dir/security"
  rm -f "$state_dir/identity.json" \
    "$state_dir/kazik-outbox.sqlite"* \
    "$state_dir/high-telemetry.sqlite"*
  rmdir "$state_dir" 2>/dev/null || true
else
  # A dedicated HF_STATE_DIR belongs to this agent and can be removed whole.
  rm -rf -- "$state_dir"
fi
rmdir /etc/honeyforge 2>/dev/null || true
rm -f "$0"
