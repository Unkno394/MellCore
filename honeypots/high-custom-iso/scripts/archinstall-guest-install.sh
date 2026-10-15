#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

disk=/dev/vda
root_partition=${disk}1
repo_mount=/run/hf-arch-repo
bootstrap_keyring_filename=archlinux-keyring-20260909-1-any.pkg.tar.zst
current_step=ARCHINSTALL_INITIALIZATION
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

run_bounded() {
  error_code=$1
  seconds=$2
  detail=$3
  shift 3
  if timeout "$seconds" "$@"; then
    return 0
  else
    status=$?
  fi
  if [ "$status" -eq 124 ]; then
    fail_install "$error_code" "$detail timed out after ${seconds}s"
  fi
  fail_install "$error_code" "$detail failed with exit status $status"
}

stop_live_unit() {
  unit=$1
  if timeout 5 systemctl is-active --quiet "$unit"; then
    run_bounded ARCH_OFFLINE_SERVICE_STOP_FAILED 20 "stopping $unit" systemctl stop "$unit"
  else
    status=$?
    [ "$status" -ne 124 ] || fail_install ARCH_OFFLINE_SERVICE_STOP_FAILED "checking $unit timed out after 5s"
  fi
  if timeout 5 systemctl is-active --quiet "$unit"; then
    fail_install ARCH_OFFLINE_SERVICE_STOP_FAILED "$unit remained active"
  else
    status=$?
    [ "$status" -ne 124 ] || fail_install ARCH_OFFLINE_SERVICE_STOP_FAILED "checking stopped $unit timed out after 5s"
  fi
}

finish_or_report() {
  status=$?
  trap - EXIT
  rm -f /run/hf-installing || true
  mountpoint -q /mnt && umount -R /mnt >/dev/null 2>&1 || true
  mountpoint -q "$repo_mount" && umount "$repo_mount" >/dev/null 2>&1 || true
  if [ "$status" -ne 0 ] && [ "$failure_reported" = false ]; then
    persist_failure "$current_step" "unexpected command failure"
    echo "HF_INSTALL_FAILED:$current_step:unexpected command failure" >&2
  fi
  exit "$status"
}

trap finish_or_report EXIT
trap 'current_step=ARCHINSTALL_INTERRUPTED; exit 1' HUP INT TERM

[ -b "$disk" ] || fail_install ARCH_TARGET_DISK_MISSING "target disk /dev/vda is absent"
for command in archinstall pacman wipefs parted partprobe udevadm mkfs.ext4 mount \
  umount mountpoint blkid arch-chroot base64 install sync awk grep sed tail python3 pacman-key \
  systemctl timeout; do
  command -v "$command" >/dev/null || fail_install INSTALL_MEDIA_COMPONENT_MISSING "$command"
done

# The live environment is intentionally isolated. Stop any service inherited
# from an older cached ISO before touching the keyring; the remastered v4 ISO
# also masks the network-dependent units before boot.
for unit in systemd-time-wait-sync.service systemd-timesyncd.service \
  reflector.service reflector.timer archlinux-keyring-wkd-sync.service \
  archlinux-keyring-wkd-sync.timer pacman-init.service; do
  stop_live_unit "$unit"
done
timedatectl set-ntp false >/dev/null 2>&1 || true

[ -s /usr/share/pacman/keyrings/archlinux.gpg ] ||
  fail_install ARCH_PACMAN_KEYRING_SOURCE_MISSING "bundled Arch keyring is absent"
run_bounded ARCH_PACMAN_KEYRING_INIT_FAILED 120 "pacman keyring initialization" \
  pacman-key --init
run_bounded ARCH_PACMAN_KEYRING_POPULATE_FAILED 120 "populating bundled Arch keyring" \
  pacman-key --populate archlinux
if key_list=$(timeout 30 pacman-key --list-keys 2>&1); then
  :
else
  status=$?
  [ "$status" -ne 124 ] || fail_install ARCH_PACMAN_KEYRING_NOT_READY "keyring readiness check timed out after 30s"
  fail_install ARCH_PACMAN_KEYRING_NOT_READY "keyring readiness check failed with exit status $status"
fi
printf '%s\n' "$key_list" | grep -Eq '^pub[[:space:]]' ||
  fail_install ARCH_PACMAN_KEYRING_NOT_READY "populated keyring contains no public keys"
[ -s /etc/pacman.d/gnupg/trustdb.gpg ] ||
  fail_install ARCH_PACMAN_KEYRING_NOT_READY "pacman trust database is absent"

archinstall_version=$(archinstall --version 2>&1 | sed -n 's/.*\(3\.0\.[0-9][0-9]*\).*/\1/p' | head -n 1)
case "$archinstall_version" in
  3.0.8|3.0.9) : ;;
  *) fail_install ARCHINSTALL_VERSION_UNSUPPORTED "expected ArchISO archinstall 3.0.8 or 3.0.9, found ${archinstall_version:-unknown}" ;;
esac
archinstall_help=$(archinstall --advanced --help 2>&1) ||
  fail_install ARCHINSTALL_CLI_UNSUPPORTED "archinstall --advanced --help failed"
for option in --config --creds --silent --offline --skip-version-check --skip-ntp --skip-wkd --dry-run; do
  printf '%s\n' "$archinstall_help" | grep -F -- "$option" >/dev/null ||
    fail_install ARCHINSTALL_CLI_UNSUPPORTED "archinstall $archinstall_version lacks $option"
done

install -d -m 0755 "$repo_mount"
repo_device=$(blkid -L HF_ARCH_REPO 2>/dev/null || true)
[ -n "$repo_device" ] && [ -b "$repo_device" ] ||
  fail_install ARCH_REPO_MEDIA_MISSING "read-only HF_ARCH_REPO media is absent"
run_step ARCH_REPO_MOUNT_FAILED mount -o ro,nosuid,nodev,noexec "$repo_device" "$repo_mount"
for database in core/os/x86_64/core.db extra/os/x86_64/extra.db HF-ARCH-REPO.json; do
  [ -s "$repo_mount/$database" ] || fail_install ARCH_REPO_MEDIA_INVALID "$database is absent"
done

metadata_error=
if ! metadata_error=$(python3 - "$repo_mount" <<'PY'
import hashlib, json, pathlib, re, sys

root = pathlib.Path(sys.argv[1])
safe = re.compile(r"^[A-Za-z0-9@._+:-]+$")

def fail(code, detail):
    print(f"{code}:{detail}")
    raise SystemExit(1)

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

try:
    manifest = json.loads((root / "HF-ARCH-REPO.json").read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError):
    fail("ARCH_REPO_METADATA_INVALID", "manifest cannot be decoded")
if manifest.get("format_version") != 3 or manifest.get("snapshot") != "2026-09-10":
    fail("ARCH_REPO_METADATA_INVALID", "unexpected repository format or snapshot")
if manifest.get("source") != "https://archive.archlinux.org/repos/2026/09/10":
    fail("ARCH_REPO_METADATA_INVALID", "unexpected repository source")
if manifest.get("architecture") != "x86_64" or manifest.get("database_signatures_required") is not False:
    fail("ARCH_REPO_METADATA_INVALID", "unexpected repository architecture or signature policy")
databases = manifest.get("databases")
if not isinstance(databases, dict) or set(databases) != {"core", "extra"}:
    fail("ARCH_REPO_METADATA_INVALID", "database digest set is incomplete")
for repository, expected in databases.items():
    path = root / repository / "os" / "x86_64" / f"{repository}.db"
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        fail("ARCH_REPO_METADATA_INVALID", f"invalid {repository} database digest")
    try:
        actual = sha256_file(path)
    except OSError:
        fail("ARCH_REPO_METADATA_INVALID", f"cannot read {repository}.db")
    if actual != expected:
        fail("ARCH_REPO_METADATA_INVALID", f"{repository}.db checksum mismatch")
keyring = manifest.get("bootstrap_keyring")
if keyring != {
    "version": "20260909-1",
    "filename": "archlinux-keyring-20260909-1-any.pkg.tar.zst",
    "sha256": "6a8ea16f51d3b305c18322d5884ca959f12c32a3f186873090fdc18465605293",
    "signature_sha256": "5942acd5b5e27a45051c447b8054696465872e834af1a5bd3cb85e2881cf6cf8",
}:
    fail("ARCH_REPO_KEYRING_INVALID", "unexpected bootstrap keyring")
keyring_path = root / "core" / "os" / "x86_64" / keyring["filename"]
try:
    if sha256_file(keyring_path) != keyring["sha256"]:
        fail("ARCH_REPO_KEYRING_INVALID", "bootstrap keyring checksum mismatch")
    if sha256_file(keyring_path.with_name(keyring_path.name + ".sig")) != keyring["signature_sha256"]:
        fail("ARCH_REPO_KEYRING_INVALID", "bootstrap keyring signature checksum mismatch")
except OSError:
    fail("ARCH_REPO_KEYRING_INVALID", "bootstrap keyring or signature is absent")
packages = manifest.get("packages")
if not isinstance(packages, list) or not packages:
    fail("ARCH_REPO_METADATA_INVALID", "package manifest is empty")
for item in packages:
    if not isinstance(item, dict):
        fail("ARCH_REPO_METADATA_INVALID", "invalid package record")
    repository = item.get("repository")
    filename = item.get("filename")
    expected = item.get("sha256")
    if repository not in {"core", "extra"} or not isinstance(filename, str) or not safe.fullmatch(filename):
        fail("ARCH_REPO_METADATA_INVALID", "unsafe package record")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        fail("ARCH_REPO_METADATA_INVALID", f"invalid digest for {filename}")
    package = root / repository / "os" / "x86_64" / filename
    signature = package.with_name(package.name + ".sig")
    if not signature.is_file() or signature.stat().st_size == 0:
        fail("ARCH_REPO_PACKAGE_SIGNATURE_MISSING", filename)
    try:
        actual = sha256_file(package)
    except OSError:
        fail("ARCH_REPO_PACKAGE_MISSING", filename)
    if actual != expected:
        fail("ARCH_REPO_PACKAGE_CHECKSUM_MISMATCH", filename)
PY
); then
  case "$metadata_error" in
    ARCH_REPO_PACKAGE_SIGNATURE_MISSING:*)
      fail_install ARCH_REPO_PACKAGE_SIGNATURE_MISSING "${metadata_error#*:}" ;;
    ARCH_REPO_PACKAGE_MISSING:*)
      fail_install ARCH_REPO_PACKAGE_MISSING "${metadata_error#*:}" ;;
    ARCH_REPO_PACKAGE_CHECKSUM_MISMATCH:*)
      fail_install ARCH_REPO_PACKAGE_CHECKSUM_MISMATCH "${metadata_error#*:}" ;;
    ARCH_REPO_KEYRING_INVALID:*)
      fail_install ARCH_REPO_KEYRING_INVALID "${metadata_error#*:}" ;;
    *) fail_install ARCH_REPO_METADATA_INVALID "${metadata_error#*:}" ;;
  esac
fi

cat > /etc/pacman.conf <<EOF
[options]
Architecture = auto
CheckSpace
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Required
ParallelDownloads = 1

[core]
Server = file://$repo_mount/\$repo/os/\$arch

[extra]
Server = file://$repo_mount/\$repo/os/\$arch
EOF

verify_package_signature() {
  package_path=$1
  expired_code=$2
  timeout_code=$3
  invalid_code=$4
  package_name=${package_path##*/}
  signature_log=/tmp/hf-package-signature.log
  if timeout 30 pacman-key --verify "$package_path.sig" "$package_path" > "$signature_log" 2>&1; then
    signature_status=0
  else
    signature_status=$?
  fi
  if grep -Eiq 'key has expired|expired key|key[^[:alnum:]]+expired|signature has expired|\[expired\]|EXPKEYSIG|KEYEXPIRED' "$signature_log"; then
    rm -f "$signature_log"
    fail_install "$expired_code" "$package_name"
  fi
  if [ "$signature_status" -eq 124 ]; then
    rm -f "$signature_log"
    fail_install "$timeout_code" "$package_name"
  fi
  if [ "$signature_status" -ne 0 ]; then
    rm -f "$signature_log"
    fail_install "$invalid_code" "$package_name"
  fi
  rm -f "$signature_log"
}

# The updated keyring is anchored by pinned SHA-256 values in the repository
# manifest and must also be signed by a key trusted by the bundled ArchISO
# keyring before it can replace any trust material.
bootstrap_keyring_path="$repo_mount/core/os/x86_64/$bootstrap_keyring_filename"
verify_package_signature "$bootstrap_keyring_path" \
  ARCH_REPO_KEYRING_SIGNING_KEY_EXPIRED ARCH_REPO_KEYRING_SIGNATURE_TIMEOUT \
  ARCH_REPO_KEYRING_SIGNATURE_INVALID
run_bounded ARCH_REPO_KEYRING_INSTALL_FAILED 120 "installing approved Arch keyring" \
  pacman --config /etc/pacman.conf -U --noconfirm "$bootstrap_keyring_path"
run_bounded ARCH_PACMAN_KEYRING_POPULATE_FAILED 120 "populating updated Arch keyring" \
  pacman-key --populate archlinux
pacman -Q archlinux-keyring 2>/dev/null | grep -F "archlinux-keyring 20260909-1" >/dev/null ||
  fail_install ARCH_REPO_KEYRING_INSTALL_FAILED "approved keyring version is not active"
run_step ARCH_REPO_DATABASE_SYNC_FAILED pacman -Sy --noconfirm

# Resolve exactly what archinstall 3.0.x and the HoneyForge post-install need.
# This does not install into the live image and therefore does not consume cowspace.
package_roots='base base-devel linux linux-firmware mkinitcpio grub openssh qemu-guest-agent audit python amd-ucode intel-ucode'
package_list=/tmp/hf-arch-package-list
pacman -Sp --print-format '%f' $package_roots > "$package_list" ||
  fail_install ARCH_REPO_DEPENDENCY_CHECK_FAILED "pacman could not resolve the offline package set"
[ -s "$package_list" ] || fail_install ARCH_REPO_DEPENDENCY_CHECK_FAILED "pacman returned an empty package set"
while IFS= read -r package_file; do
  case "$package_file" in
    ''|*/*|*..*) fail_install ARCH_REPO_MEDIA_INVALID "unsafe package filename" ;;
  esac
  package_path=
  for repository in core extra; do
    candidate="$repo_mount/$repository/os/x86_64/$package_file"
    if [ -s "$candidate" ]; then
      package_path=$candidate
      break
    fi
  done
  [ -n "$package_path" ] || fail_install ARCH_REPO_PACKAGE_MISSING "$package_file"
  [ -s "$package_path.sig" ] || fail_install ARCH_REPO_PACKAGE_SIGNATURE_MISSING "$package_file"
  verify_package_signature "$package_path" \
    ARCH_REPO_PACKAGE_SIGNING_KEY_EXPIRED ARCH_REPO_PACKAGE_SIGNATURE_TIMEOUT \
    ARCH_REPO_PACKAGE_SIGNATURE_INVALID
done < "$package_list"

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
parted -s -m "$disk" unit s print > "$partition_table" ||
  fail_install ARCH_PARTITION_VERIFY_FAILED "could not inspect the target partition table"
awk -F: 'NR == 2 { if ($6 != "msdos") exit 1; table = 1 }
  $1 == "1" { start = $2; sub(/s$/, "", start); if (start < 2048 || $5 != "ext4" || $7 !~ /(^|,)boot[,;]?$/) exit 1; root = 1 }
  END { exit !(table && root) }' "$partition_table" ||
  fail_install ARCH_PARTITION_VERIFY_FAILED "expected an msdos table and bootable ext4 partition 1 after the BIOS embedding gap"
run_step ARCH_ROOT_FILESYSTEM_FAILED mkfs.ext4 -F -L arch-root "$root_partition"
run_step ARCH_ROOT_MOUNT_FAILED mount "$root_partition" /mnt

config=/tmp/hf-archinstall-config.json
credentials=/tmp/hf-archinstall-credentials.json
cat > "$config" <<EOF
{
  "app_config": null,
  "archinstall-language": "English",
  "auth_config": {},
  "audio_config": null,
  "bootloader": "Grub",
  "custom_commands": [],
  "disk_config": {"config_type": "pre_mounted_config", "mountpoint": "/mnt"},
  "hostname": "@@HOSTNAME@@",
  "kernels": ["linux"],
  "locale_config": {"kb_layout": "us", "sys_enc": "UTF-8", "sys_lang": "en_US.UTF-8"},
  "mirror_config": null,
  "network_config": {"type": "iso"},
  "ntp": false,
  "packages": ["grub", "openssh", "qemu-guest-agent", "audit", "python"],
  "parallel_downloads": 0,
  "profile_config": {"gfx_driver": null, "greeter": null, "profile": {}},
  "script": "guided",
  "services": ["systemd-networkd", "systemd-resolved", "sshd", "qemu-guest-agent", "auditd"],
  "swap": false,
  "timezone": "UTC",
  "version": "$archinstall_version"
}
EOF
cat > "$credentials" <<'EOF'
{
  "root_enc_password": null,
  "users": [
    {"enc_password": "@@ANALYST_PASSWORD_HASH@@", "groups": ["systemd-journal"], "sudo": true, "username": "analyst"}
  ]
}
EOF
chmod 0600 "$config" "$credentials"

archinstall_log=/var/log/honeyforge-archinstall.log
if ! archinstall --advanced --config "$config" --creds "$credentials" --silent \
  --offline --skip-version-check --skip-ntp --skip-wkd --dry-run > "$archinstall_log" 2>&1; then
  tail -n 40 "$archinstall_log" |
    sed -E 's/\$[0-9A-Za-z]+\$[^"[:space:]]+/<redacted-password-hash>/g' >&2 || true
  fail_install ARCHINSTALL_CONFIG_INVALID "archinstall $archinstall_version rejected the generated configuration"
fi
current_step=ARCHINSTALL_EXECUTION_FAILED
if ! archinstall --advanced --config "$config" --creds "$credentials" --silent \
  --offline --skip-version-check --skip-ntp --skip-wkd > "$archinstall_log" 2>&1; then
  tail -n 40 "$archinstall_log" |
    sed -E 's/\$[0-9A-Za-z]+\$[^"[:space:]]+/<redacted-password-hash>/g' >&2 || true
  fail_install ARCHINSTALL_EXECUTION_FAILED "archinstall $archinstall_version failed; see sanitized serial log"
fi

[ -f /mnt/etc/os-release ] || fail_install ARCHINSTALL_TARGET_INVALID "/mnt is not an installed system"
grep -Eq '^ID=arch$|^ID="arch"$' /mnt/etc/os-release ||
  fail_install ARCHINSTALL_TARGET_INVALID "installed os-release is not Arch Linux"
root_uuid=$(blkid -s UUID -o value "$root_partition") ||
  fail_install ARCH_ROOT_UUID_FAILED "could not read root filesystem UUID"
grep -F "UUID=$root_uuid" /mnt/etc/fstab >/dev/null ||
  fail_install ARCH_FSTAB_VERIFY_FAILED "fstab does not reference the root filesystem UUID"

run_step ARCH_POST_CONFIG_DIRECTORY_FAILED install -d -m 0755 \
  /mnt/etc/systemd/network /mnt/etc/ssh/sshd_config.d /mnt/etc/audit/rules.d \
  /mnt/usr/local/lib/honeyforge /mnt/srv/operations/backups
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
printf '%s' '@@SENSOR_B64@@' | base64 -d > /mnt/usr/local/lib/honeyforge/high-telemetry-sensor ||
  fail_install ARCH_TELEMETRY_CONFIG_FAILED "could not install telemetry sensor"
printf '%s' '@@AUDIT_SENSOR_B64@@' | base64 -d > /mnt/usr/local/lib/honeyforge/high_telemetry_audit.py ||
  fail_install ARCH_TELEMETRY_CONFIG_FAILED "could not install audit sensor"
printf '%s' '@@SERVICE_B64@@' | base64 -d > /mnt/etc/systemd/system/high-telemetry.service ||
  fail_install ARCH_TELEMETRY_CONFIG_FAILED "could not install telemetry service"
printf '%s' '@@AUDIT_RULES_B64@@' | base64 -d > /mnt/etc/audit/rules.d/90-honeyforge.rules ||
  fail_install ARCH_TELEMETRY_CONFIG_FAILED "could not install audit rules"
run_step ARCH_TELEMETRY_CONFIG_FAILED chmod 0755 /mnt/usr/local/lib/honeyforge/high-telemetry-sensor
# archinstall requires either a root password or a declared sudo user for an
# unattended configuration. Satisfy that validation during installation, then
# remove the temporary privilege before the target is ever booted.
run_step ARCH_USER_PRIVILEGE_REMOVE_FAILED arch-chroot /mnt usermod -G systemd-journal analyst
run_step ARCH_USER_PRIVILEGE_REMOVE_FAILED rm -f /mnt/etc/sudoers.d/00_archinstall
if arch-chroot /mnt id -nG analyst | grep -Eq '(^|[[:space:]])wheel([[:space:]]|$)'; then
  fail_install ARCH_USER_PRIVILEGE_REMOVE_FAILED "analyst retained the wheel group"
fi
run_step ARCH_ROOT_LOCK_FAILED arch-chroot /mnt passwd -l root
run_step ARCH_SERVICE_ENABLE_FAILED arch-chroot /mnt systemctl enable \
  systemd-networkd systemd-resolved sshd qemu-guest-agent auditd high-telemetry.service
run_step ARCH_TELEMETRY_PYTHON_VERIFY_FAILED arch-chroot /mnt python3 -m py_compile \
  /usr/local/lib/honeyforge/high_telemetry_audit.py

# Do not leave the ephemeral file:// repository configured on the installed system.
cat > /mnt/etc/pacman.d/mirrorlist <<'EOF'
Server = https://archive.archlinux.org/repos/2026/09/10/$repo/os/$arch
EOF

cat > /mnt/etc/default/grub <<'EOF'
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
run_step ARCH_GRUB_CONFIG_FAILED arch-chroot /mnt grub-mkconfig -o /boot/grub/grub.cfg

for boot_file in /mnt/boot/vmlinuz-linux /mnt/boot/initramfs-linux.img \
  /mnt/boot/grub/i386-pc/core.img /mnt/boot/grub/grub.cfg; do
  [ -s "$boot_file" ] || fail_install ARCH_BOOT_ARTIFACT_MISSING "$boot_file"
done
for program in sshd qemu-ga python3; do
  arch-chroot /mnt sh -c "command -v '$program'" >/dev/null ||
    fail_install ARCH_INSTALLED_COMPONENT_MISSING "$program"
done
grep -F '/vmlinuz-linux' /mnt/boot/grub/grub.cfg >/dev/null ||
  fail_install ARCH_GRUB_VERIFY_FAILED "GRUB does not reference the installed kernel"
grep -F "$root_uuid" /mnt/boot/grub/grub.cfg >/dev/null ||
  fail_install ARCH_GRUB_VERIFY_FAILED "GRUB does not reference the root filesystem UUID"

printf '%s\n' installed > /mnt/etc/honeyforge-installed ||
  fail_install ARCH_INSTALL_MARKER_WRITE_FAILED "could not write installation marker"
run_step ARCH_DISK_SYNC_FAILED sync
run_step ARCH_ROOT_UNMOUNT_FAILED umount /mnt
run_step ARCH_REPO_UNMOUNT_FAILED umount "$repo_mount"

current_step=ARCH_POWER_OFF_REQUEST_FAILED
systemctl --no-block poweroff || fail_install ARCH_POWER_OFF_REQUEST_FAILED "systemd rejected poweroff"
rm -f /run/hf-installing
trap - EXIT HUP INT TERM
echo HF_INSTALL_COMPLETE
exit 0
