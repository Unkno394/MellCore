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
`config-2` ISO. The agent publishes the selected public TCP port to guest RDP/3389 using the shared
High firewall chains. The guest remains on the isolated libvirt network: inbound forwarding permits
only that RDP flow, while guest access to the host and unrelated forwarding remain denied. SSH
Dispatcher sharing is not used for RDP.

The first image build requires KVM, HashiCorp Packer, the Windows image tools, at least 5 GiB of
available memory and 55 GiB of free disk. An administrator must register the Windows Evaluation
media and trusted checksums before deployment. The archive installs the builder alongside the agent;
it does not invent source URLs, checksums or license approval. Existing approved prepared images can
be used without Packer.

The original ISO/Unattend scripts remain for manifests carrying the legacy
`InstallMediaAndDisk + UnattendedInstall` profile. Guest event telemetry still requires a reviewed
Windows sensor; this recipe does not synthesize it.
