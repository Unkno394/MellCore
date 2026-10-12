# Reproducible offline guest preparation

The runtime cloud-init seed performs no `apt update` and does not download packages. Build the
package bundle on a disposable Ubuntu 24.04 amd64 staging host with repository access:

    sh offline/build-package-bundle.sh /srv/hf-bundles/noble-amd64

`SHA256SUMS` pins every downloaded deb and `VERSIONS` records the selected primary versions.
Review and archive both files with the bundle. On a build host with libguestfs, prepare a derived
image without booting it:

    sh offline/prepare-image.sh \
      /var/lib/honeyforge/images/noble-server-cloudimg-amd64.img \
      /var/lib/honeyforge/images/noble-honeyforge-amd64.qcow2 \
      /srv/hf-bundles/noble-amd64

The second script verifies all package hashes, installs `auditd`, `audispd-plugins` and
`qemu-guest-agent` with `dpkg`, verifies the required executables, runs `qemu-img check`, and emits
an image checksum. Deploy High with this derived immutable base image.

`tlog` is deliberately not installed by default. Audit `execve/execveat` is a kernel observation
of executed programs but cannot see shell built-ins. A future tlog integration must define a
redaction policy and a tested parser before terminal input is persisted; passwords and arbitrary
terminal contents must not be collected by default.
