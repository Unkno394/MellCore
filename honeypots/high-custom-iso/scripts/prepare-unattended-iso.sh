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
  rm -rf "$syslinux_dir" "$instance_dir/arch-media-probe"
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
  python3 - "$syslinux_dir" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
configs = sorted(root.rglob("*.cfg"))
main = root / "archiso_sys.cfg"
if not main.is_file():
    raise SystemExit("Arch SYSLINUX tree lacks archiso_sys.cfg")

default_label = None
serial_append = False
for path in configs:
    text = path.read_text(encoding="utf-8")
    labels = list(re.finditer(r"(?mi)^\s*LABEL\s+(\S+)", text))
    for index, label in enumerate(labels):
        end = labels[index + 1].start() if index + 1 < len(labels) else len(text)
        block = text[label.start():end]
        if "vmlinuz-linux" in block and "initramfs-linux.img" in block:
            default_label = default_label or label.group(1)

    rendered = []
    for line in text.splitlines(keepends=True):
        if re.match(r"(?i)^\s*APPEND\s+", line) and "console=ttyS0" not in line:
            ending = "\n" if line.endswith("\n") else ""
            line = line.rstrip("\r\n") + " console=ttyS0,115200n8" + ending
        if re.match(r"(?i)^\s*APPEND\s+", line) and "console=ttyS0" in line:
            serial_append = True
        rendered.append(line)
    path.write_text("".join(rendered), encoding="utf-8")

if default_label is None:
    raise SystemExit("Arch SYSLINUX config has no x86_64 live kernel entry")
if not serial_append:
    raise SystemExit("Arch SYSLINUX config has no kernel APPEND directive for serial boot")
with main.open("a", encoding="utf-8") as config:
    config.write(
        "\n# HoneyForge deterministic serial boot\n"
        f"DEFAULT {default_label}\nPROMPT 0\nTIMEOUT 1\nSERIAL 0 115200\n"
    )
PY
  rm -rf "$instance_dir/arch-media-probe"
  xorriso -indev "$base_iso" -outdev "$instance_dir/unattended.iso.tmp" -boot_image any replay \
    -map "$syslinux_dir" /boot/syslinux -commit >/dev/null 2>&1
fi
mv "$instance_dir/unattended.iso.tmp" "$instance_dir/unattended.iso"
chmod 0600 "$password_file" "$instance_dir/unattended.iso"
