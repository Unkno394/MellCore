# hf-image-builder

`hf-image-builder` creates the immutable, generalized Windows Server 2022 Evaluation x64 QCOW2
consumed by `honeypots/high-windows-rdp`. It does not call libvirt, change the host firewall, or
publish RDP/WinRM. Packer's temporary WinRM forward and VNC listener bind only to `127.0.0.1`;
QEMU user networking uses `restrict=on`, so the build guest cannot initiate external connections.

The builder deliberately contains no invented or mutable Windows, VirtIO, or Cloudbase checksum.
Normal Windows deployments read the root-protected approved-source catalog at
`/etc/honeyforge/image-sources/windows-server-2022.json`; end users do not provide URLs or hashes.
If the prepared image is absent, `hf-agent` invokes this builder once, verifies the result, and then
continues the existing Prepared QCOW2 lifecycle.

## Host dependencies

Ubuntu packages: `qemu-system-x86`, `qemu-utils`, `libguestfs-tools`, `wimtools`, `xorriso`, and
`curl`; install HashiCorp Packer from HashiCorp's signed Ubuntu repository. The
template pins `github.com/hashicorp/qemu` to `1.1.3`; `packer init` downloads and checksum-verifies
that plugin in the temporary build workspace.
The invoking account needs read/write access to `/dev/kvm` and write access to the HoneyForge
directories. The preflight requires at least 5 GiB `MemAvailable` and 55 GiB free disk.

## One-time administrator approval

Microsoft's Evaluation Center requires an administrator to review the terms and obtain the selected
ISO. Obtain every checksum through the team's trusted release process; do not calculate a hash from
an untrusted download and treat that same hash as approval. Register the media once:

```sh
sudo /usr/local/lib/honeyforge/hf-image-builder/hf-image-builder register-sources \
  --windows-iso /root/approved/WindowsServer2022.iso \
  --windows-sha256 TRUSTED_MICROSOFT_SHA256 \
  --image-index APPROVED_WIM_INDEX \
  --image-name 'EXACT_WIM_IMAGE_NAME' \
  --edition-id ServerDatacenterEval \
  --virtio-url APPROVED_FEDORA_HTTPS_URL \
  --virtio-sha256 TRUSTED_VIRTIO_SHA256 \
  --virtio-allowed-host APPROVED_FEDORA_HOST \
  --cloudbase-url APPROVED_CLOUDBASE_HTTPS_URL \
  --cloudbase-sha256 TRUSTED_CLOUDBASE_SHA256 \
  --cloudbase-allowed-host APPROVED_CLOUDBASE_HOST \
  --approved-by ADMIN_IDENTITY \
  --accept-microsoft-evaluation-license
```

This verifies and copies the Windows ISO into the protected local source directory and atomically
creates the non-world-writable catalog. It refuses to replace either an existing approved ISO with
different bytes or an existing catalog. VirtIO and Cloudbase artifacts are subsequently fetched by
HTTPS from only the catalog allowlist and are checked before entering the cache.

The builder first downloads to `/var/cache/honeyforge/hf-image-builder`, verifies every cached
file on every run, extracts `install.wim`, and requires the configured index/name/edition to be
Windows Server 2022 build 20348 x64 Desktop Experience. It stages the Server 2022 VirtIO storage,
network and serial drivers, QEMU Guest Agent, and Cloudbase-Init configured only for OpenStack
ConfigDrive. The one-time builder account, WinRM rule, answer files, and password are removed
before Cloudbase's Sysprep `/generalize /oobe /shutdown`.

Normally the agent starts the build automatically on the first Windows deployment. An administrator
can run the same operation explicitly:

```sh
sudo /usr/local/lib/honeyforge/hf-image-builder/hf-image-builder build --cleanup-sources
```

On success the builder validates and atomically publishes, without replacement:

```text
/var/lib/honeyforge/images/windows-server-prepared.qcow2
/var/lib/honeyforge/images/windows-server-prepared.qcow2.sha256
```

The checksum manifest is linked last. Its presence is the handoff/readiness signal for the
existing Windows Prepared adapter. If either final path already exists, the build refuses to
start; existing overlays are therefore never retargeted to a different base.

Offline recheck and explicit source cleanup:

```sh
sudo ./tools/hf-image-builder/hf-image-builder verify
sudo /usr/local/lib/honeyforge/hf-image-builder/hf-image-builder cleanup-sources
```

Stage logs are written with mode `0600` to `/var/log/honeyforge/hf-image-builder.log`; URLs and
one-time passwords are not logged.

Evaluation media may only be used under Microsoft's applicable evaluation terms. The operator is
responsible for approving the exact Microsoft ISO URL and independently trusted checksum.
