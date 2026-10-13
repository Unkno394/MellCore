#!/bin/sh
set -eu

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
  /etc/honeyforge/hysteria-client.yaml /etc/honeyforge/dispatcher.json
rm -rf /var/lib/honeyforge/traps /var/lib/honeyforge/high \
  /var/lib/honeyforge/inbox /var/lib/honeyforge/security
rm -f /var/lib/honeyforge/identity.json \
  /var/lib/honeyforge/kazik-outbox.sqlite* \
  /var/lib/honeyforge/high-telemetry.sqlite*
rmdir /etc/honeyforge /var/lib/honeyforge 2>/dev/null || true
rm -f "$0"
