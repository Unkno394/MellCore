# High Windows RDP recipe

The default Windows profile consumes a generalized, Sysprep-prepared QCOW2 at
`/var/lib/honeyforge/images/windows-server-prepared.qcow2`. The image builder handoff is two local,
immutable files:

* `windows-server-prepared.qcow2`
* `windows-server-prepared.qcow2.sha256` (the first field is the 64-character SHA-256)

If both files are absent, the adapter invokes the installed `hf-image-builder`. It uses the
administrator-approved catalog at `/etc/honeyforge/image-sources/windows-server-2022.json`; no
source URL or checksum is accepted from the end-user deployment command. A partially published
image/manifest pair is never rebuilt or replaced automatically.

Publish the image with an atomic no-replace operation, then publish the checksum manifest last as
the readiness marker. Never overwrite or remove a published base: existing per-trap overlays
retain its pathname as their backing file. Before every new overlay the agent verifies the
SHA-256, rejects chained base images, checks the QCOW2 format and runs `qemu-img check`.

The prepared image must include VirtIO storage/network/serial drivers, QEMU Guest Agent, RDP, and
Cloudbase-Init configured for the OpenStack ConfigDrive service with `inject_user_password=true`.
Cloudbase-Init receives a unique instance UUID, hostname, `hfadmin` account and password through a
`config-2` ISO. The adapter discovers the isolated DHCP lease and waits for RDP on 3389, but creates
no DNAT or forwarding exception; RDP is reachable only from the KVM host.

The ISO/Unattend path validates that index 2 is a supported Windows Server 2022 evaluation image,
waits for installed-system RDP, ejects all installation media, cold-boots the disk and requires RDP
again before writing `installed-disk-verified`. Guest event telemetry still requires a reviewed
Windows sensor; this recipe does not synthesize it. Like the prepared-image path, legacy ISO RDP
remains host-only and never creates DNAT automatically.
