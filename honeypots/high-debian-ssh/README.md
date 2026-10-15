# High Debian SSH

Debian 12 uses the official `cloud.debian.org` genericcloud QCOW2 and verifies it against the
HTTPS `SHA512SUMS` manifest on every cached reuse. The adapter shares the existing High isolated
network/firewall and telemetry sensor, while keeping a Debian-specific cloud-init profile.

The upstream image omits `qemu-guest-agent`. Before libvirt starts a new instance, the recipe uses
`virt-customize` against that instance's overlay (never the verified base) to install Debian's
signed `qemu-guest-agent` and `auditd` packages. The running High VM remains on the isolated
network; first-boot cloud-init requires both services before telemetry readiness succeeds.
