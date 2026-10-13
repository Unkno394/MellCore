# High Arch SSH recipe

This recipe creates a cloud-init seed and an isolated KVM/libvirt VM for an Arch SSH High trap.
It reuses the reviewed host-side isolation and DNAT implementation from `high-ubuntu-ssh`.

Before deployment set `HF_HIGH_ARCH_IMAGE_URL` and `HF_HIGH_ARCH_IMAGE_SHA256` (64 lowercase or
uppercase hexadecimal characters). The image is downloaded only over HTTPS and is verified before
it is atomically installed at `/var/lib/honeyforge/images/arch-linux-x86_64-cloudimg.qcow2`.
The Arch cloud image must already contain `cloud-init`, OpenSSH, Python, auditd, and qemu-guest-agent;
the isolated guest deliberately never contacts a package mirror during first boot.
