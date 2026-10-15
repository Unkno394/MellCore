#!/bin/sh
set -eu
base_iso=${1:?verified installation ISO}; instance_id=${2:?instance UUID}; flavor=${3:?ubuntu, debian or arch}
root_dir=${HF_HIGH_ROOT:-/var/lib/honeyforge/high}; instance_dir="$root_dir/$instance_id"
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$script_dir/../../high-ubuntu-ssh/scripts/firewall-common.sh"
validate_instance_id "$instance_id"
case "$flavor" in ubuntu|debian|arch) ;; *) echo "unsupported unattended ISO flavor: $flavor" >&2; exit 1 ;; esac
for command in xorriso openssl python3; do command -v "$command" >/dev/null; done
[ -r "$base_iso" ]
arch_recipe_revision=arch-offline-init-v4
if [ "$flavor" = arch ]; then
  for command in mksquashfs unsquashfs sha512sum; do
    command -v "$command" >/dev/null || {
      echo "HF_HIGH_ERROR code=DEPENDENCY_MISSING stage=dependencies: Arch ISO preparation requires $command" >&2
      exit 1
    }
  done
  if [ -s "$instance_dir/unattended.iso" ] &&
     [ -f "$instance_dir/unattended-arch.version" ] &&
     grep -Fx "$arch_recipe_revision" "$instance_dir/unattended-arch.version" >/dev/null; then
    exit 0
  fi
fi
mkdir -p "$instance_dir/iso-payload/nocloud" "$instance_dir/iso-payload/honeyforge"
rm -f "$instance_dir/unattended.iso.tmp"
password_file="$instance_dir/ssh-password"
if [ -r "$password_file" ]; then analyst_password=$(cat "$password_file"); else
  analyst_password=$(openssl rand -base64 24 | tr -d '\n'); umask 077; printf '%s\n' "$analyst_password" > "$password_file"
fi
[ -n "$analyst_password" ] || { echo 'generated SSH password is empty' >&2; exit 1; }
password_hash=$(printf '%s' "$analyst_password" | openssl passwd -6 -stdin)
hostname="hf-$(printf '%s' "$instance_id" | tr -d '-' | cut -c1-24)"
shared_guest_dir="$script_dir/../../high-ubuntu-ssh/guest"
python3 - "$shared_guest_dir/high_telemetry_sensor.py" "$shared_guest_dir/high_telemetry_audit.py" <<'PY'
import pathlib, sys
for filename in sys.argv[1:]: compile(pathlib.Path(filename).read_bytes(), filename, "exec")
PY
cp "$shared_guest_dir/high_telemetry_sensor.py" "$instance_dir/iso-payload/honeyforge/high-telemetry-sensor"
cp "$shared_guest_dir/high_telemetry_audit.py" "$instance_dir/iso-payload/honeyforge/high_telemetry_audit.py"
cp "$shared_guest_dir/high-telemetry.service" "$instance_dir/iso-payload/honeyforge/high-telemetry.service"
cp "$shared_guest_dir/90-honeyforge.rules" "$instance_dir/iso-payload/honeyforge/90-honeyforge.rules"
printf 'instance-id: %s\nlocal-hostname: %s\n' "$instance_id" "$hostname" > "$instance_dir/iso-payload/nocloud/meta-data"

if [ "$flavor" = ubuntu ]; then
  offline_bundle=${HF_HIGH_UBUNTU_OFFLINE_BUNDLE:-$(dirname "$root_dir")/images/ubuntu-24.04-offline-packages}
  sh "$script_dir/../../high-ubuntu-ssh/offline/build-package-bundle.sh" "$offline_bundle"
  rm -rf "$instance_dir/iso-payload/honeyforge/offline-packages"
  cp -a "$offline_bundle" "$instance_dir/iso-payload/honeyforge/offline-packages"
  cat > "$instance_dir/iso-payload/nocloud/user-data" <<EOF
#cloud-config
autoinstall:
  version: 1
  refresh-installer:
    update: no
  apt:
    fallback: offline-install
  source:
    id: ubuntu-server
  identity:
    hostname: $hostname
    username: analyst
    password: '$password_hash'
  ssh:
    install-server: true
    allow-pw: true
  storage:
    layout:
      name: direct
  shutdown: poweroff
  late-commands:
    - install -d -m 0755 /target/usr/local/lib/honeyforge /target/etc/audit/rules.d /target/srv/operations/backups
    - cp -a /cdrom/honeyforge/offline-packages /target/opt/honeyforge-offline-packages
    - curtin in-target -- sh -c 'cd /opt/honeyforge-offline-packages && sha256sum -c SHA256SUMS && (dpkg -i ./*.deb || true)'
    - curtin in-target -- sh -c 'cd /opt/honeyforge-offline-packages && dpkg -i ./*.deb'
    - curtin in-target -- sh -c 'command -v qemu-ga && command -v auditctl && command -v python3 && command -v sshd'
    - cp /cdrom/honeyforge/high-telemetry-sensor /target/usr/local/lib/honeyforge/high-telemetry-sensor
    - cp /cdrom/honeyforge/high_telemetry_audit.py /target/usr/local/lib/honeyforge/high_telemetry_audit.py
    - cp /cdrom/honeyforge/high-telemetry.service /target/etc/systemd/system/high-telemetry.service
    - cp /cdrom/honeyforge/90-honeyforge.rules /target/etc/audit/rules.d/90-honeyforge.rules
    - curtin in-target -- chmod 0755 /usr/local/lib/honeyforge/high-telemetry-sensor
    - curtin in-target -- systemctl enable ssh qemu-guest-agent auditd high-telemetry.service
    - curtin in-target -- sh -c 'printf "%s\\n" installed > /etc/honeyforge-installed'
    - rm -rf /target/opt/honeyforge-offline-packages
EOF
  grub="$instance_dir/grub.cfg"
  xorriso -osirrox on -indev "$base_iso" -extract /boot/grub/grub.cfg "$grub" >/dev/null 2>&1 || {
    echo 'Ubuntu media lacks /boot/grub/grub.cfg required for autoinstall' >&2; exit 1;
  }
  python3 - "$grub" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1]); text = p.read_text()
text, count = re.subn(r'(?m)^(\s*linux\s+/casper/vmlinuz)(?![^\n]*\bautoinstall\b)', r'\1 autoinstall ds=nocloud\\;s=/cdrom/nocloud/ console=ttyS0,115200n8', text)
if not count and "/casper/vmlinuz" not in text: raise SystemExit("Ubuntu GRUB config has no supported casper kernel entry")
p.write_text(text)
PY
  xorriso -indev "$base_iso" -outdev "$instance_dir/unattended.iso.tmp" -boot_image any replay \
    -map "$grub" /boot/grub/grub.cfg \
    -map "$instance_dir/iso-payload/nocloud" /nocloud \
    -map "$instance_dir/iso-payload/honeyforge" /honeyforge -commit >/dev/null 2>&1
elif [ "$flavor" = debian ]; then
  cat > "$instance_dir/preseed.cfg" <<EOF
d-i debian-installer/locale string en_US.UTF-8
d-i keyboard-configuration/xkb-keymap select us
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string $hostname
d-i passwd/root-login boolean false
d-i passwd/user-fullname string Analyst
d-i passwd/username string analyst
d-i passwd/user-password-crypted password $password_hash
d-i clock-setup/utc boolean true
d-i time/zone string UTC
d-i partman-auto/method string regular
d-i partman-auto/choose_recipe select atomic
d-i partman/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
tasksel tasksel/first multiselect standard, ssh-server
d-i apt-setup/use_mirror boolean false
d-i pkgsel/include string openssh-server qemu-guest-agent auditd python3
popularity-contest popularity-contest/participate boolean false
d-i grub-installer/only_debian boolean true
d-i finish-install/reboot_in_progress note
d-i preseed/late_command string \
  in-target mkdir -p /opt/honeyforge /usr/local/lib/honeyforge /etc/audit/rules.d /srv/operations/backups; \
  cp /cdrom/honeyforge/high-telemetry-sensor /target/usr/local/lib/honeyforge/high-telemetry-sensor; \
  cp /cdrom/honeyforge/high_telemetry_audit.py /target/usr/local/lib/honeyforge/high_telemetry_audit.py; \
  cp /cdrom/honeyforge/high-telemetry.service /target/etc/systemd/system/high-telemetry.service; \
  cp /cdrom/honeyforge/90-honeyforge.rules /target/etc/audit/rules.d/90-honeyforge.rules; \
  in-target chmod 0755 /usr/local/lib/honeyforge/high-telemetry-sensor; \
  in-target systemctl enable ssh qemu-guest-agent auditd high-telemetry.service; \
  in-target sh -c 'printf "%s\\n" installed > /etc/honeyforge-installed'
EOF
  grub="$instance_dir/grub.cfg"
  xorriso -osirrox on -indev "$base_iso" -extract /boot/grub/grub.cfg "$grub" >/dev/null 2>&1 || {
    echo 'Debian media lacks /boot/grub/grub.cfg required for preseed' >&2; exit 1;
  }
  python3 - "$grub" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1]); text = p.read_text()
text, count = re.subn(r'(?m)^(\s*linux\s+/install\.amd/vmlinuz)(?![^\n]*\bauto=true\b)', r'\1 auto=true priority=critical preseed/file=/cdrom/preseed.cfg console=ttyS0,115200n8', text)
if not count and "/install.amd/vmlinuz" not in text: raise SystemExit("Debian GRUB config has no supported amd64 installer entry")
p.write_text(text)
PY
  isolinux="$instance_dir/isolinux-txt.cfg"
  xorriso -osirrox on -indev "$base_iso" -extract /isolinux/txt.cfg "$isolinux" >/dev/null 2>&1 || {
    echo 'Debian media lacks /isolinux/txt.cfg required for BIOS preseed' >&2; exit 1;
  }
  python3 - "$isolinux" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1]); text = p.read_text()
text, count = re.subn(r'(?mi)^(\s*append\s+)(?![^\n]*\bauto=true\b)', r'\1auto=true priority=critical preseed/file=/cdrom/preseed.cfg console=ttyS0,115200n8 ', text)
if not count and "auto=true" not in text: raise SystemExit("Debian ISOLINUX config has no append entry")
p.write_text(text)
PY
  xorriso -indev "$base_iso" -outdev "$instance_dir/unattended.iso.tmp" -boot_image any replay \
    -map "$grub" /boot/grub/grub.cfg -map "$isolinux" /isolinux/txt.cfg \
    -map "$instance_dir/preseed.cfg" /preseed.cfg \
    -map "$instance_dir/iso-payload/honeyforge" /honeyforge -commit >/dev/null 2>&1
elif [ "$flavor" = arch ]; then
  # Official Arch installation media boots in BIOS mode from /boot/syslinux. It does not
  # provide the Ubuntu/Debian-style /boot/grub/grub.cfg that older recipes assumed.
  syslinux_dir="$instance_dir/boot-syslinux"
  airootfs="$instance_dir/airootfs.sfs"
  rebuilt_airootfs="$instance_dir/airootfs.sfs.tmp"
  airootfs_sha="$instance_dir/airootfs.sha512"
  serial_root="$instance_dir/arch-live-root"
  serial_verify="$instance_dir/arch-serial-verify"
  serial_listing="$instance_dir/arch-live-root.list"
  rm -rf "$syslinux_dir" "$instance_dir/arch-media-probe" "$serial_root" "$serial_verify"
  rm -f "$airootfs" "$rebuilt_airootfs" "$airootfs_sha" "$airootfs_sha.tmp" "$serial_listing"
  xorriso -osirrox on -indev "$base_iso" -extract /boot/syslinux "$syslinux_dir" >/dev/null 2>&1 || {
    echo 'Arch media lacks /boot/syslinux required for BIOS serial installation' >&2; exit 1;
  }
  mkdir -p "$instance_dir/arch-media-probe"
  for media_path in /arch/boot/x86_64/vmlinuz-linux /arch/boot/x86_64/initramfs-linux.img /EFI/BOOT/BOOTx64.EFI; do
    probe="$instance_dir/arch-media-probe/$(basename "$media_path")"
    xorriso -osirrox on -indev "$base_iso" -extract "$media_path" "$probe" >/dev/null 2>&1 || {
      echo "Arch media lacks required boot artefact $media_path" >&2; exit 1;
    }
  done
  xorriso -osirrox on -indev "$base_iso" -extract /arch/x86_64/airootfs.sfs "$airootfs" >/dev/null 2>&1 || {
    echo 'HF_HIGH_ERROR code=ARCH_LIVE_ROOTFS_MISSING stage=installation: Arch media lacks /arch/x86_64/airootfs.sfs' >&2; exit 1;
  }
  chmod 0600 "$airootfs"
  python3 - "$syslinux_dir" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
main = root / "archiso_sys.cfg"
if not main.is_file():
    raise SystemExit("Arch SYSLINUX tree lacks archiso_sys.cfg")
entry_path = root / "archiso_sys-linux.cfg"
if not entry_path.is_file():
    raise SystemExit("Arch SYSLINUX tree lacks archiso_sys-linux.cfg")

main_text = main.read_text(encoding="utf-8")
includes = re.findall(r"(?mi)^\s*INCLUDE\s+(\S+)", main_text)
if not any(pathlib.PurePosixPath(value).name == entry_path.name for value in includes):
    raise SystemExit("Arch archiso_sys.cfg does not include archiso_sys-linux.cfg")

entry_text = entry_path.read_text(encoding="utf-8")
labels = list(re.finditer(r"(?mi)^\s*LABEL\s+(\S+)", entry_text))
selected = [
    (label, labels[index + 1].start() if index + 1 < len(labels) else len(entry_text))
    for index, label in enumerate(labels)
    if label.group(1) == "arch64"
]
if len(selected) != 1:
    raise SystemExit("Arch archiso_sys-linux.cfg must contain exactly one LABEL arch64")
label, end = selected[0]
start = label.start()
block = entry_text[start:end]
if not re.search(r"(?mi)^\s*LINUX\s+/arch/boot/x86_64/vmlinuz-linux(?:\s|$)", block):
    raise SystemExit("Arch BIOS label arch64 has an unexpected kernel")
if not re.search(r"(?mi)^\s*INITRD\s+/arch/boot/x86_64/initramfs-linux\.img(?:\s|$)", block):
    raise SystemExit("Arch BIOS label arch64 has an unexpected initramfs")
append_pattern = re.compile(r"(?mi)^(\s*APPEND\s+)([^\r\n]*)")

def serial_args(match):
    args = re.sub(
        r"(?<!\S)console=tty(?:0|S0)(?:,[^\s]+)?(?=\s|$)",
        "",
        match.group(2),
    )
    args = " ".join(args.split()) + " console=tty0 console=ttyS0,115200n8"
    return match.group(1) + args

block, append_count = append_pattern.subn(serial_args, block, count=1)
if append_count != 1:
    raise SystemExit("Arch BIOS label arch64 has no unique APPEND directive")
if not re.search(r"(?m)^\s*APPEND\s+.*\bconsole=tty0\b.*\bconsole=ttyS0,115200n8\b", block):
    raise SystemExit("Arch BIOS label arch64 was not configured for the serial console")
patched_entry = entry_text[:start] + block + entry_text[end:]

# Avoid accumulating contradictory directives when an interrupted deployment is
# retried against the same per-instance tree.
main_text = re.sub(
    r"(?mi)^\s*(?:DEFAULT|PROMPT|TIMEOUT|SERIAL)\b[^\r\n]*(?:\r?\n|$)",
    "",
    main_text,
)
patched_main = (
    "# HoneyForge deterministic serial boot\n"
    "SERIAL 0 115200\nDEFAULT arch64\nPROMPT 0\nTIMEOUT 1\n"
    + main_text
)
if not re.search(r"(?m)^DEFAULT\s+arch64\s*$", patched_main):
    raise SystemExit("Arch SYSLINUX default is not the BIOS label arch64")
if not re.search(r"(?mi)^\s*LABEL\s+arch64\s*$", patched_entry):
    raise SystemExit("Arch SYSLINUX default label is absent from archiso_sys-linux.cfg")

entry_path.write_text(patched_entry, encoding="utf-8")
main.write_text(patched_main, encoding="utf-8")
PY

  # console=ttyS0 makes systemd-getty-generator instantiate serial-getty, but the
  # stock monthly ArchISO only configures root autologin for tty1. Extract the
  # per-instance copy of airootfs.sfs, patch that single filesystem tree and
  # rebuild it. Supplying an overlay directory as an additional SquashFS root
  # renames the colliding top-level /etc to /etc_1 and leaves the drop-in unused.
  unsquashfs -no-progress -d "$serial_root" "$airootfs" >/dev/null || {
    echo 'HF_HIGH_ERROR code=ARCH_LIVE_ROOTFS_PREPARATION_FAILED stage=installation: could not extract the per-instance Arch live root' >&2; exit 1;
  }
  serial_dropin="$serial_root/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf"
  serial_wants="$serial_root/etc/systemd/system/getty.target.wants"
  mkdir -p "$(dirname "$serial_dropin")" "$serial_wants"
  cat > "$serial_dropin" <<'EOF'
[Service]
ExecStart=
ExecStart=-/usr/bin/agetty --noreset --noclear --autologin root --keep-baud 115200,57600,38400,9600 - ${TERM}
EOF
  serial_link="$serial_wants/serial-getty@ttyS0.service"
  rm -f "$serial_link"
  ln -s /usr/lib/systemd/system/serial-getty@.service "$serial_link"

  # The live image has no routed egress by design. Prevent services which wait
  # for Internet time or mirrors from delaying multi-user.target, and detach
  # pacman-init from time-sync.target so the bundled keyring can be populated
  # entirely from /usr/share/pacman/keyrings.
  systemd_root="$serial_root/etc/systemd/system"
  mkdir -p "$systemd_root"
  offline_units='systemd-time-wait-sync.service systemd-timesyncd.service reflector.service reflector.timer archlinux-keyring-wkd-sync.service archlinux-keyring-wkd-sync.timer'
  for unit in $offline_units; do
    rm -f "$systemd_root/$unit"
    ln -s /dev/null "$systemd_root/$unit"
  done
  pacman_init_dropin="$systemd_root/pacman-init.service.d/honeyforge-offline.conf"
  mkdir -p "$(dirname "$pacman_init_dropin")"
  cat > "$pacman_init_dropin" <<'EOF'
[Unit]
After=
After=etc-pacman.d-gnupg.mount
Wants=
EOF
  chmod 0755 "$(dirname "$serial_dropin")" "$serial_wants"
  chmod 0755 "$(dirname "$pacman_init_dropin")"
  chmod 0644 "$serial_dropin" "$pacman_init_dropin"
  mksquashfs "$serial_root" "$rebuilt_airootfs" -noappend -no-progress -no-recovery -processors 1 -mem 256M >/dev/null || {
    echo 'HF_HIGH_ERROR code=ARCH_LIVE_ROOTFS_PREPARATION_FAILED stage=installation: could not rebuild the per-instance Arch live root' >&2; exit 1;
  }
  chmod 0600 "$rebuilt_airootfs"
  mv "$rebuilt_airootfs" "$airootfs"
  unsquashfs -no-progress -d "$serial_verify" "$airootfs" \
    etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf \
    etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service \
    etc/systemd/system/pacman-init.service.d/honeyforge-offline.conf \
    etc/systemd/system/systemd-time-wait-sync.service \
    etc/systemd/system/systemd-timesyncd.service \
    etc/systemd/system/reflector.service \
    etc/systemd/system/reflector.timer \
    etc/systemd/system/archlinux-keyring-wkd-sync.service \
    etc/systemd/system/archlinux-keyring-wkd-sync.timer >/dev/null || {
    echo 'HF_HIGH_ERROR code=ARCH_LIVE_ROOTFS_VERIFY_FAILED stage=installation: prepared Arch live root lacks required serial or offline initialization files' >&2; exit 1;
  }
  grep -Fx '[Service]' "$serial_verify/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf" >/dev/null &&
  grep -Fx 'ExecStart=' "$serial_verify/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf" >/dev/null &&
  grep -Fx 'ExecStart=-/usr/bin/agetty --noreset --noclear --autologin root --keep-baud 115200,57600,38400,9600 - ${TERM}' \
    "$serial_verify/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf" >/dev/null || {
    echo 'HF_HIGH_ERROR code=ARCH_SERIAL_GETTY_VERIFY_FAILED stage=installation: serial root autologin override is invalid' >&2; exit 1;
  }
  [ -L "$serial_verify/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service" ] &&
  [ "$(readlink "$serial_verify/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service")" = /usr/lib/systemd/system/serial-getty@.service ] || {
    echo 'HF_HIGH_ERROR code=ARCH_SERIAL_GETTY_VERIFY_FAILED stage=installation: serial-getty activation link is invalid' >&2; exit 1;
  }
  grep -Fx 'After=' "$serial_verify/etc/systemd/system/pacman-init.service.d/honeyforge-offline.conf" >/dev/null &&
  grep -Fx 'After=etc-pacman.d-gnupg.mount' "$serial_verify/etc/systemd/system/pacman-init.service.d/honeyforge-offline.conf" >/dev/null &&
  grep -Fx 'Wants=' "$serial_verify/etc/systemd/system/pacman-init.service.d/honeyforge-offline.conf" >/dev/null || {
    echo 'HF_HIGH_ERROR code=ARCH_OFFLINE_INIT_VERIFY_FAILED stage=installation: pacman-init offline override is invalid' >&2; exit 1;
  }
  for unit in $offline_units; do
    [ -L "$serial_verify/etc/systemd/system/$unit" ] &&
    [ "$(readlink "$serial_verify/etc/systemd/system/$unit")" = /dev/null ] || {
      echo "HF_HIGH_ERROR code=ARCH_OFFLINE_INIT_VERIFY_FAILED stage=installation: $unit is not masked in the live image" >&2
      exit 1
    }
  done
  unsquashfs -no-progress -l "$airootfs" > "$serial_listing" || {
    echo 'HF_HIGH_ERROR code=ARCH_SERIAL_GETTY_VERIFY_FAILED stage=installation: could not list the rebuilt Arch live root' >&2; exit 1;
  }
  if grep -E '(^|/)etc_1(/|$)' "$serial_listing" >/dev/null; then
    echo 'HF_HIGH_ERROR code=ARCH_LIVE_ROOTFS_PREPARATION_FAILED stage=installation: rebuilt Arch live root contains a conflicting etc_1 directory' >&2; exit 1;
  fi
  (cd "$instance_dir" && sha512sum airootfs.sfs > airootfs.sha512.tmp)
  mv "$airootfs_sha.tmp" "$airootfs_sha"
  serial_entry="$syslinux_dir/archiso_sys-linux.cfg"
  [ -f "$serial_entry" ] && grep -F 'console=ttyS0,115200n8' "$serial_entry" >/dev/null || {
    echo 'HF_HIGH_ERROR code=ARCH_SYSLINUX_SERIAL_INVALID stage=installation: the selected ArchISO Syslinux entry was not patched for ttyS0' >&2; exit 1;
  }
  xorriso -indev "$base_iso" -outdev "$instance_dir/unattended.iso.tmp" -boot_image any replay \
    -map "$syslinux_dir/archiso_sys.cfg" /boot/syslinux/archiso_sys.cfg \
    -map "$serial_entry" /boot/syslinux/archiso_sys-linux.cfg \
    -map "$airootfs" /arch/x86_64/airootfs.sfs \
    -map "$airootfs_sha" /arch/x86_64/airootfs.sha512 \
    -commit >/dev/null 2>&1
  rm -rf "$instance_dir/arch-media-probe" "$serial_root" "$serial_verify"
  rm -f "$airootfs" "$rebuilt_airootfs" "$airootfs_sha" "$airootfs_sha.tmp" "$serial_listing"
fi
mv "$instance_dir/unattended.iso.tmp" "$instance_dir/unattended.iso"
chmod 0600 "$password_file" "$instance_dir/unattended.iso"
if [ "$flavor" = arch ]; then
  printf '%s\n' "$arch_recipe_revision" > "$instance_dir/unattended-arch.version.tmp"
  chmod 0600 "$instance_dir/unattended-arch.version.tmp"
  mv "$instance_dir/unattended-arch.version.tmp" "$instance_dir/unattended-arch.version"
fi
