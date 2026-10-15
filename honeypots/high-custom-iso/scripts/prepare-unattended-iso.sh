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
  cat > "$instance_dir/iso-payload/nocloud/user-data" <<EOF
#cloud-config
autoinstall:
  version: 1
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
  packages: [qemu-guest-agent, auditd, python3]
  late-commands:
    - install -d -m 0755 /target/usr/local/lib/honeyforge /target/etc/audit/rules.d /target/srv/operations/backups
    - cp /cdrom/honeyforge/high-telemetry-sensor /target/usr/local/lib/honeyforge/high-telemetry-sensor
    - cp /cdrom/honeyforge/high_telemetry_audit.py /target/usr/local/lib/honeyforge/high_telemetry_audit.py
    - cp /cdrom/honeyforge/high-telemetry.service /target/etc/systemd/system/high-telemetry.service
    - cp /cdrom/honeyforge/90-honeyforge.rules /target/etc/audit/rules.d/90-honeyforge.rules
    - curtin in-target -- chmod 0755 /usr/local/lib/honeyforge/high-telemetry-sensor
    - curtin in-target -- systemctl enable ssh qemu-guest-agent auditd high-telemetry.service
    - curtin in-target -- sh -c 'printf "%s\\n" installed > /etc/honeyforge-installed'
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
  grub="$instance_dir/grub.cfg"
  xorriso -osirrox on -indev "$base_iso" -extract /boot/grub/grub.cfg "$grub" >/dev/null 2>&1 || {
    echo 'Arch media lacks /boot/grub/grub.cfg required for serial unattended installation' >&2; exit 1;
  }
  python3 - "$grub" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1]); text = p.read_text()
text, count = re.subn(r'(?m)^(\s*linux\s+/arch/boot/x86_64/vmlinuz-linux)(?![^\n]*console=ttyS0)', r'\1 console=ttyS0,115200n8', text)
if not count and "/arch/boot/x86_64/vmlinuz-linux" not in text: raise SystemExit("Arch GRUB config has no supported x86_64 kernel entry")
p.write_text(text)
PY
  syslinux_dir="$instance_dir/syslinux"
  xorriso -osirrox on -indev "$base_iso" -extract /syslinux "$syslinux_dir" >/dev/null 2>&1 || {
    echo 'Arch media lacks /syslinux required for BIOS serial installation' >&2; exit 1;
  }
  python3 - "$syslinux_dir" <<'PY'
import pathlib, re, sys
changed = 0
for p in pathlib.Path(sys.argv[1]).glob("*.cfg"):
    text = p.read_text()
    rendered, count = re.subn(r'(?mi)^(\s*append\s+)(?![^\n]*console=ttyS0)', r'\1console=ttyS0,115200n8 ', text)
    if count: p.write_text(rendered); changed += count
if not changed: raise SystemExit("Arch SYSLINUX config has no append entry")
PY
  xorriso -indev "$base_iso" -outdev "$instance_dir/unattended.iso.tmp" -boot_image any replay \
    -map "$grub" /boot/grub/grub.cfg -map "$syslinux_dir" /syslinux -commit >/dev/null 2>&1
fi
mv "$instance_dir/unattended.iso.tmp" "$instance_dir/unattended.iso"
chmod 0600 "$password_file" "$instance_dir/unattended.iso"
