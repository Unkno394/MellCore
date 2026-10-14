# High Arch SSH recipe

This recipe creates a cloud-init seed and an isolated KVM/libvirt VM for an Arch SSH High trap.
It reuses the reviewed host-side isolation and DNAT implementation from `high-ubuntu-ssh`.

The pinned default is the official Arch Linux `arch-boxes` cloud image release
`v20261001.604814`, downloaded from `geo.mirror.pkgbuild.com` over HTTPS. Its SHA-256 is pinned in
`scripts/download-base-image.sh`; both a new download and every cached reuse are verified. A bad
cache entry is never replaced automatically because existing overlays may depend on that pathname.

Root may select a newer approved release with both `HF_HIGH_ARCH_IMAGE_URL` and
`HF_HIGH_ARCH_IMAGE_SHA256`. Use an immutable versioned Arch mirror URL and the matching official
`.SHA256` file. The official image contains cloud-init, OpenSSH, Python (a cloud-init dependency),
and qemu-guest-agent. `auditd` is optional: when absent, SSH/session and sensor telemetry remain
available, while audit-backed process/file/network events are not emitted. The isolated guest does
not contact package mirrors during first boot.

The current image does not render the NoCloud v2 network configuration into a networkd unit early
enough to obtain DHCP. The recipe therefore injects `05-honeyforge-high.network` with
`virt-customize --no-network` into each new overlay. The verified base QCOW2 is never modified.

On Ubuntu the agent installs `acl` and `libguestfs-tools` for this adapter and grants
`libvirt-qemu` only the ACLs needed to traverse the private standalone state directory, read the
verified base/seed, write the overlay, and create the telemetry socket. The generated password and
rendered cloud-init remain root-only.
