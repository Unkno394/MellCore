# High Debian SSH

Debian 12 uses the official `cloud.debian.org` genericcloud QCOW2 and verifies it against the
HTTPS `SHA512SUMS` manifest on every cached reuse. The adapter shares the existing High isolated
network/firewall and telemetry sensor, while keeping a Debian-specific cloud-init profile.
