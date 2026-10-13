# hf-image-builder

`hf-image-builder` creates the immutable, generalized Windows Server 2022 Evaluation x64 QCOW2
consumed by `honeypots/high-windows-rdp`. It does not call libvirt, change the host firewall, or
publish RDP/WinRM. Packer's temporary WinRM forward and VNC listener bind only to `127.0.0.1`;
QEMU user networking uses `restrict=on`, so the build guest cannot initiate external connections.

The builder deliberately contains no Windows, VirtIO, or Cloudbase download URL/checksum. Supply
an approved HTTPS URL and a SHA-256 obtained through the team's trusted release process. The
Windows URL host must be a Microsoft download host; dependency host allowlists are explicit.

## Host dependencies

Ubuntu packages: `qemu-system-x86`, `qemu-utils`, `libguestfs-tools`, `wimtools`, `xorriso`, and
`curl`; install HashiCorp Packer from HashiCorp's signed Ubuntu repository. The
template pins `github.com/hashicorp/qemu` to `1.1.7`; `packer init` downloads and checksum-verifies
that plugin in the temporary build workspace.
The invoking account needs read/write access to `/dev/kvm` and write access to the HoneyForge
directories. The preflight requires at least 5 GiB `MemAvailable` and 55 GiB free disk.

Copy `image-builder.env.example` to a root-readable `/etc/honeyforge/image-builder.env` (do not
commit the populated file):

```sh
HF_WINDOWS_EVALUATION_LICENSE_ACCEPTED=yes
HF_WINDOWS_ISO_URL='REPLACE_WITH_APPROVED_MICROSOFT_HTTPS_URL'
HF_WINDOWS_ISO_SHA256='REPLACE_WITH_TRUSTED_64_HEX_SHA256'
HF_WINDOWS_IMAGE_INDEX='REPLACE_AFTER_DISM_OR_WIMLIB_INSPECTION'
HF_WINDOWS_IMAGE_NAME='REPLACE_WITH_EXACT_WIM_IMAGE_NAME'
HF_WINDOWS_IMAGE_EDITION_ID='ServerDatacenterEval'

HF_VIRTIO_ISO_URL='REPLACE_WITH_APPROVED_VIRTIO_HTTPS_URL'
HF_VIRTIO_ISO_SHA256='REPLACE_WITH_TRUSTED_64_HEX_SHA256'
HF_VIRTIO_ISO_ALLOWED_HOSTS='REPLACE_WITH_APPROVED_HOST'

HF_CLOUDBASE_MSI_URL='REPLACE_WITH_APPROVED_CLOUDBASE_HTTPS_URL'
HF_CLOUDBASE_MSI_SHA256='REPLACE_WITH_TRUSTED_64_HEX_SHA256'
HF_CLOUDBASE_MSI_ALLOWED_HOSTS='REPLACE_WITH_APPROVED_HOST'
```

The builder first downloads to `/var/cache/honeyforge/hf-image-builder`, verifies every cached
file on every run, extracts `install.wim`, and requires the configured index/name/edition to be
Windows Server 2022 build 20348 x64 Desktop Experience. It stages the Server 2022 VirtIO storage,
network and serial drivers, QEMU Guest Agent, and Cloudbase-Init configured only for OpenStack
ConfigDrive. The one-time builder account, WinRM rule, answer files, and password are removed
before Cloudbase's Sysprep `/generalize /oobe /shutdown`.

Run from the repository checkout. Loading the configuration inside `sudo` keeps the trust anchors
in the root-readable file:

```sh
sudo sh -c 'set -a; . /etc/honeyforge/image-builder.env; set +a; exec "$1" build --cleanup-sources' sh "$(pwd)/tools/hf-image-builder/hf-image-builder"
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
sudo sh -c 'set -a; . /etc/honeyforge/image-builder.env; set +a; exec "$1" cleanup-sources' sh "$(pwd)/tools/hf-image-builder/hf-image-builder"
```

Stage logs are written with mode `0600` to `/var/log/honeyforge/hf-image-builder.log`; URLs and
one-time passwords are not logged.

Evaluation media may only be used under Microsoft's applicable evaluation terms. The operator is
responsible for approving the exact Microsoft ISO URL and independently trusted checksum.
