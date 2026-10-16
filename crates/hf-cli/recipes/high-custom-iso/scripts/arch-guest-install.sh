#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

disk=/dev/vda
root_partition=${disk}1
current_step=ARCH_INSTALL_INITIALIZATION
failure_reported=false

persist_failure() {
  umask 077
  printf '%s:%s\n' "$1" "$2" > /run/hf-install-failure.tmp &&
    mv /run/hf-install-failure.tmp /run/hf-install-failure || true
}

fail_install() {
  current_step=$1
  failure_reported=true
  persist_failure "$1" "$2"
  echo "HF_INSTALL_FAILED:$1:$2" >&2
  exit 1
}

run_step() {
  current_step=$1
  shift
  "$@" || fail_install "$current_step" "command failed"
}

finish_or_report() {
  status=$?
  trap - EXIT
  rm -f /run/hf-installing || true
  if [ "$status" -ne 0 ] && [ "$failure_reported" = false ]; then
    persist_failure "$current_step" "unexpected command failure"
    echo "HF_INSTALL_FAILED:$current_step:unexpected command failure" >&2
  fi
  exit "$status"
}

trap finish_or_report EXIT
trap 'current_step=ARCH_INSTALL_INTERRUPTED; exit 1' HUP INT TERM

[ -b "$disk" ] || fail_install ARCH_TARGET_DISK_MISSING "target disk /dev/vda is absent"
# Installation is intentionally offline; do not wait for NTP or package repositories.
timedatectl set-ntp false >/dev/null 2>&1 || true
for command in sshd qemu-ga python3 grub-install grub-mkconfig mkinitcpio \
  wipefs parted partprobe udevadm mkfs.ext4 mount umount mountpoint genfstab \
  arch-chroot blkid base64 install sync awk grep cp; do
  command -v "$command" >/dev/null || fail_install INSTALL_MEDIA_COMPONENT_MISSING "$command"
done

if mountpoint -q /mnt; then
  run_step ARCH_PREVIOUS_ROOT_UNMOUNT_FAILED umount -R /mnt
fi
run_step ARCH_DISK_WIPE_FAILED wipefs -a "$disk"
run_step ARCH_PARTITION_TABLE_FAILED parted -s "$disk" mklabel msdos
run_step ARCH_ROOT_PARTITION_FAILED parted -s "$disk" mkpart primary ext4 1MiB 100%
run_step ARCH_BOOT_FLAG_FAILED parted -s "$disk" set 1 boot on
run_step ARCH_PARTITION_RESCAN_FAILED partprobe "$disk"
run_step ARCH_PARTITION_SETTLE_FAILED udevadm settle
[ -b "$root_partition" ] || fail_install ARCH_ROOT_PARTITION_MISSING "$root_partition was not created"

partition_table=/tmp/hf-arch-partitions
if ! parted -s -m "$disk" unit s print > "$partition_table"; then
  fail_install ARCH_PARTITION_VERIFY_FAILED "could not inspect the target partition table"
fi
awk -F: 'NR == 2 { if ($6 != "msdos") exit 1; table = 1 }
  $1 == "1" { start = $2; sub(/s$/, "", start); if (start < 2048 || $5 != "ext4" || $7 !~ /(^|,)boot[,;]?$/) exit 1; root = 1 }
  END { exit !(table && root) }' "$partition_table" ||
  fail_install ARCH_PARTITION_VERIFY_FAILED "expected an msdos table and bootable ext4 partition 1 after the BIOS embedding gap"
run_step ARCH_PARTITION_VERIFY_CLEANUP_FAILED rm -f "$partition_table"

run_step ARCH_ROOT_FILESYSTEM_FAILED mkfs.ext4 -F -L arch-root "$root_partition"
run_step ARCH_ROOT_MOUNT_FAILED mount "$root_partition" /mnt
# The High network deliberately has no routed egress. Clone the reviewed Arch live root instead
# of using the repository bootstrapper, which would require access outside the isolation boundary.
for tree in bin boot etc home lib lib64 opt root sbin srv usr var; do
  if [ -e "/$tree" ]; then
    run_step ARCH_ROOTFS_COPY_FAILED cp -a "/$tree" /mnt/
  fi
done
run_step ARCH_LIVE_CONFIG_CLEANUP_FAILED rm -rf \
  /mnt/etc/systemd/system/getty@tty1.service.d \
  /mnt/etc/systemd/system/choose-mirror.service
if ! genfstab -U /mnt > /mnt/etc/fstab; then
  fail_install ARCH_FSTAB_GENERATION_FAILED "genfstab failed"
fi
root_uuid=$(blkid -s UUID -o value "$root_partition") ||
  fail_install ARCH_ROOT_UUID_FAILED "could not read the root filesystem UUID"
[ -n "$root_uuid" ] || fail_install ARCH_ROOT_UUID_FAILED "root filesystem UUID is empty"
awk -v expected="UUID=$root_uuid" '$1 == expected && $2 == "/" && $3 == "ext4" { found = 1 } END { exit !found }' /mnt/etc/fstab ||
  fail_install ARCH_FSTAB_VERIFY_FAILED "fstab does not mount the ext4 root filesystem by UUID"

printf '%s\n' '@@HOSTNAME@@' > /mnt/etc/hostname ||
  fail_install ARCH_HOSTNAME_CONFIG_FAILED "could not write /etc/hostname"
printf '%s\n' '127.0.0.1 localhost' '::1 localhost' '127.0.1.1 @@HOSTNAME@@.localdomain @@HOSTNAME@@' > /mnt/etc/hosts ||
  fail_install ARCH_HOSTNAME_CONFIG_FAILED "could not write /etc/hosts"
run_step ARCH_USER_CREATE_FAILED arch-chroot /mnt useradd -m -G systemd-journal -s /bin/bash analyst
printf '%s\n' 'analyst:@@ANALYST_PASSWORD_HASH@@' | arch-chroot /mnt chpasswd -e ||
  fail_install ARCH_USER_PASSWORD_FAILED "could not set the analyst password"
run_step ARCH_ROOT_LOCK_FAILED arch-chroot /mnt passwd -l root
run_step ARCH_CONFIG_DIRECTORY_FAILED install -d -m 0755 \
  /mnt/etc/systemd/network /mnt/etc/ssh/sshd_config.d /mnt/srv/operations/backups
if ! cat > /mnt/etc/systemd/network/05-honeyforge-high.network <<'EOF'
[Match]
Name=*
[Network]
DHCP=yes
IPv6AcceptRA=no
LinkLocalAddressing=no
EOF
then
  fail_install ARCH_NETWORK_CONFIG_FAILED "could not write the networkd configuration"
fi
if ! cat > /mnt/etc/ssh/sshd_config.d/90-honeyforge.conf <<'EOF'
PasswordAuthentication yes
PermitRootLogin no
X11Forwarding no
EOF
then
  fail_install ARCH_SSH_CONFIG_FAILED "could not write the sshd configuration"
fi
run_step ARCH_SERVICE_ENABLE_FAILED arch-chroot /mnt systemctl enable systemd-networkd systemd-resolved sshd qemu-guest-agent

# ArchISO carries its booted kernel below /usr/lib/modules and an archiso-only
# mkinitcpio preset. Convert it into the conventional kernel and preset layout
# expected by an installed Arch system.
set -- /mnt/usr/lib/modules/*/vmlinuz
[ "$#" -eq 1 ] && [ -f "$1" ] ||
  fail_install ARCH_KERNEL_DISCOVERY_FAILED "expected exactly one kernel image below /usr/lib/modules"
kernel_source=$1
kernel_version=$(basename "$(dirname "$kernel_source")")
[ -d "/mnt/usr/lib/modules/$kernel_version/kernel" ] ||
  fail_install ARCH_KERNEL_MODULES_MISSING "kernel modules for $kernel_version are absent"
run_step ARCH_KERNEL_INSTALL_FAILED install -Dm0644 "$kernel_source" /mnt/boot/vmlinuz-linux

if ! cat > /mnt/etc/mkinitcpio.conf <<'EOF'
MODULES=(virtio_pci virtio_blk)
BINARIES=()
FILES=()
HOOKS=(base udev autodetect microcode modconf kms keyboard keymap consolefont block filesystems fsck)
EOF
then
  fail_install ARCH_INITRAMFS_CONFIG_FAILED "could not write mkinitcpio.conf"
fi
if ! cat > /mnt/etc/mkinitcpio.d/linux.preset <<'EOF'
ALL_config="/etc/mkinitcpio.conf"
ALL_kver="/boot/vmlinuz-linux"
PRESETS=('default')
default_image="/boot/initramfs-linux.img"
EOF
then
  fail_install ARCH_INITRAMFS_CONFIG_FAILED "could not replace the live mkinitcpio preset"
fi
run_step ARCH_INITRAMFS_BUILD_FAILED arch-chroot /mnt mkinitcpio -P
[ -s /mnt/boot/vmlinuz-linux ] || fail_install ARCH_KERNEL_VERIFY_FAILED "/boot/vmlinuz-linux is absent or empty"
[ -s /mnt/boot/initramfs-linux.img ] || fail_install ARCH_INITRAMFS_VERIFY_FAILED "/boot/initramfs-linux.img is absent or empty"

if ! cat > /mnt/etc/default/grub <<'EOF'
GRUB_DEFAULT=0
GRUB_TIMEOUT=1
GRUB_DISTRIBUTOR="Arch"
GRUB_CMDLINE_LINUX_DEFAULT="console=tty0 console=ttyS0,115200n8"
GRUB_CMDLINE_LINUX=""
GRUB_PRELOAD_MODULES="part_gpt part_msdos"
GRUB_TERMINAL_INPUT="console serial"
GRUB_TERMINAL_OUTPUT="console serial"
GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1"
EOF
then
  fail_install ARCH_GRUB_CONFIG_FAILED "could not write the GRUB defaults"
fi
run_step ARCH_GRUB_INSTALL_FAILED arch-chroot /mnt grub-install --target=i386-pc --recheck "$disk"
run_step ARCH_GRUB_CONFIG_FAILED arch-chroot /mnt grub-mkconfig -o /boot/grub/grub.cfg
[ -s /mnt/boot/grub/i386-pc/core.img ] || fail_install ARCH_GRUB_VERIFY_FAILED "GRUB BIOS core image is absent"
[ -s /mnt/boot/grub/grub.cfg ] || fail_install ARCH_GRUB_VERIFY_FAILED "GRUB configuration is absent"
grep -F '/vmlinuz-linux' /mnt/boot/grub/grub.cfg >/dev/null ||
  fail_install ARCH_GRUB_VERIFY_FAILED "GRUB configuration does not reference the installed kernel"
grep -F '/initramfs-linux.img' /mnt/boot/grub/grub.cfg >/dev/null ||
  fail_install ARCH_GRUB_VERIFY_FAILED "GRUB configuration does not reference the installed initramfs"
grep -F "$root_uuid" /mnt/boot/grub/grub.cfg >/dev/null ||
  fail_install ARCH_GRUB_VERIFY_FAILED "GRUB configuration does not reference the root filesystem UUID"

printf '%s\n' installed > /mnt/etc/honeyforge-installed ||
  fail_install ARCH_INSTALL_MARKER_WRITE_FAILED "could not write the installation marker"
run_step ARCH_DISK_SYNC_FAILED sync
run_step ARCH_ROOT_UNMOUNT_FAILED umount /mnt

current_step=ARCH_POWER_OFF_REQUEST_FAILED
systemctl --no-block poweroff || fail_install ARCH_POWER_OFF_REQUEST_FAILED "systemd rejected the poweroff request"
rm -f /run/hf-installing
trap - EXIT HUP INT TERM
echo HF_INSTALL_COMPLETE
exit 0
