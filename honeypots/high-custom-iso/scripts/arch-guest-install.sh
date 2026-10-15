#!/bin/sh
set -eu
trap 'echo HF_INSTALL_FAILED:guest-script; rm -f /run/hf-installing' EXIT INT TERM
disk=/dev/vda
[ -b "$disk" ] || { echo 'HF_INSTALL_FAILED: target disk /dev/vda is absent' >&2; exit 1; }
timedatectl set-ntp true || true
for command in sshd qemu-ga auditd python3 grub-install mkinitcpio; do
  command -v "$command" >/dev/null || {
    echo "HF_INSTALL_FAILED:INSTALL_MEDIA_COMPONENT_MISSING:$command" >&2
    exit 1
  }
done
wipefs -a "$disk"
parted -s "$disk" mklabel msdos
parted -s "$disk" mkpart primary ext4 1MiB 100%
parted -s "$disk" set 1 boot on
udevadm settle
mkfs.ext4 -F -L arch-root "${disk}1"
mount "${disk}1" /mnt
# The High network deliberately has no routed egress. Clone the reviewed Arch live root instead
# of using the repository bootstrapper, which would require access outside the isolation boundary.
for tree in bin boot etc home lib lib64 opt root sbin srv usr var; do
  [ -e "/$tree" ] && cp -a "/$tree" /mnt/
done
rm -rf /mnt/etc/systemd/system/getty@tty1.service.d /mnt/etc/systemd/system/choose-mirror.service
genfstab -U /mnt > /mnt/etc/fstab
printf '%s\n' '@@HOSTNAME@@' > /mnt/etc/hostname
printf '%s\n' '127.0.0.1 localhost' '::1 localhost' '127.0.1.1 @@HOSTNAME@@.localdomain @@HOSTNAME@@' > /mnt/etc/hosts
arch-chroot /mnt useradd -m -G systemd-journal -s /bin/bash analyst
printf '%s\n' 'analyst:@@ANALYST_PASSWORD_HASH@@' | arch-chroot /mnt chpasswd -e
arch-chroot /mnt passwd -l root
install -d -m 0755 /mnt/etc/systemd/network /mnt/etc/ssh/sshd_config.d /mnt/etc/audit/rules.d /mnt/usr/local/lib/honeyforge /mnt/srv/operations/backups
cat > /mnt/etc/systemd/network/05-honeyforge-high.network <<'EOF'
[Match]
Name=en* eth*
[Network]
DHCP=yes
IPv6AcceptRA=no
LinkLocalAddressing=no
EOF
cat > /mnt/etc/ssh/sshd_config.d/90-honeyforge.conf <<'EOF'
PasswordAuthentication yes
PermitRootLogin no
X11Forwarding no
EOF
printf '%s' '@@SENSOR_B64@@' | base64 -d > /mnt/usr/local/lib/honeyforge/high-telemetry-sensor
printf '%s' '@@AUDIT_SENSOR_B64@@' | base64 -d > /mnt/usr/local/lib/honeyforge/high_telemetry_audit.py
printf '%s' '@@SERVICE_B64@@' | base64 -d > /mnt/etc/systemd/system/high-telemetry.service
printf '%s' '@@AUDIT_RULES_B64@@' | base64 -d > /mnt/etc/audit/rules.d/90-honeyforge.rules
chmod 0755 /mnt/usr/local/lib/honeyforge/high-telemetry-sensor
arch-chroot /mnt systemctl enable systemd-networkd systemd-resolved sshd qemu-guest-agent auditd high-telemetry.service
cat > /mnt/etc/mkinitcpio.conf <<'EOF'
MODULES=()
BINARIES=()
FILES=()
HOOKS=(base udev autodetect microcode modconf kms keyboard keymap consolefont block filesystems fsck)
EOF
arch-chroot /mnt mkinitcpio -P
arch-chroot /mnt grub-install --target=i386-pc "$disk"
sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="console=tty0 console=ttyS0,115200n8"/' /mnt/etc/default/grub
arch-chroot /mnt grub-mkconfig -o /boot/grub/grub.cfg
printf '%s\n' installed > /mnt/etc/honeyforge-installed
sync
rm -f /run/hf-installing
trap - EXIT INT TERM
echo HF_INSTALL_COMPLETE
systemctl poweroff
