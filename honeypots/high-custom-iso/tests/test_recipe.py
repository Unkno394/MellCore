import base64
import hashlib
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest


RECIPE = pathlib.Path(__file__).resolve().parents[1]
INSTANCE_ID = "11111111-2222-4333-8444-555555555555"


def executable(path, body):
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class CustomIsoRecipeTests(unittest.TestCase):
    def test_scripts_are_valid_shell(self):
        for script in (RECIPE / "scripts").glob("*.sh"):
            subprocess.run(["sh", "-n", str(script)], check=True)

    def test_installer_is_isolated_and_has_no_publication(self):
        launch = (RECIPE / "scripts" / "launch-iso.sh").read_text()
        check = (RECIPE / "scripts" / "check-ssh-isolated.sh").read_text()
        self.assertIn("network=$HF_HIGH_NETWORK_NAME", launch)
        self.assertIn('--cdrom "$install_iso" --boot "$install_boot"', launch)
        self.assertIn("spice,listen=127.0.0.1", launch)
        self.assertNotIn("publish-ssh", launch)
        self.assertIn("unexpected DNAT publication", check)
        self.assertIn("HF_HIGH_INPUT_CHAIN", check)
        self.assertIn("ESTABLISHED,RELATED", check)

    def test_supported_linux_iso_installers_verify_disk_boot(self):
        launch = (RECIPE / "scripts" / "launch-iso.sh").read_text()
        finalizer = (RECIPE / "scripts" / "finalize-linux-install.sh").read_text()
        arch = (RECIPE / "scripts" / "install-arch.sh").read_text()
        prepare = (RECIPE / "scripts" / "prepare-unattended-iso.sh").read_text()
        self.assertIn("ubuntu|debian", launch)
        self.assertIn('arch) sh "$script_dir/install-arch.sh"', launch)
        self.assertIn("autoinstall:", prepare)
        self.assertIn("preseed/late_command", prepare)
        self.assertIn('install_boot=cdrom,hd', launch)
        self.assertIn('--boot "$install_boot"', launch)
        self.assertIn("cdrom,hd,menu=off,useserial=on", launch)
        self.assertIn('change-media "$vm_name"', finalizer)
        self.assertIn('virsh start "$vm_name"', finalizer)
        self.assertIn("installed-disk-verified", finalizer)
        self.assertIn("virt-cat", arch)
        self.assertIn("installed-disk-verified", arch)
        guest = (RECIPE / "scripts" / "arch-guest-install.sh").read_text()
        self.assertNotIn("pacstrap", guest)
        self.assertNotIn("pacman", guest)
        self.assertIn("timedatectl set-ntp false", guest)
        self.assertIn("INSTALL_MEDIA_COMPONENT_MISSING", guest)
        self.assertIn("cp -a", guest)

    def test_installation_is_restartable_and_bounded(self):
        launch = (RECIPE / "scripts" / "launch-iso.sh").read_text()
        arch = (RECIPE / "scripts" / "install-arch.sh").read_text()
        self.assertNotIn("virsh undefine", launch)
        self.assertIn("HF_HIGH_INSTALL_TIMEOUT_SECONDS", arch)
        self.assertIn("HF_HIGH_ARCH_BOOT_TIMEOUT_SECONDS", arch)
        self.assertIn("arch-serial-console.log", arch)
        self.assertIn("arch-guest-install.b64", arch)
        self.assertIn("install-started", arch)
        self.assertIn("INSTALL_MEDIA_EJECT_FAILED", arch)

    def test_unattended_media_is_generated_per_instance(self):
        grub_by_flavor = {
            "ubuntu": "menuentry x {\n linux /casper/vmlinuz ---\n}\n",
            "debian": "menuentry x {\n linux /install.amd/vmlinuz --- quiet\n}\n",
        }
        for flavor, grub in grub_by_flavor.items():
            with self.subTest(flavor=flavor), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                fake_bin = root / "bin"
                fake_bin.mkdir()
                executable(
                    fake_bin / "xorriso",
                    "#!/bin/sh\n"
                    "last=\n"
                    "out=\n"
                    "extract=\n"
                    "source=\n"
                    "while [ \"$#\" -gt 0 ]; do\n"
                    "  case \"$1\" in\n"
                    "    -extract) shift; source=$1; shift; extract=$1 ;;\n"
                    "    -outdev) shift; out=$1 ;;\n"
                    "  esac\n"
                    "  last=$1; shift\n"
                    "done\n"
                    "if [ \"$source\" = /isolinux/txt.cfg ]; then printf '%s\\n' ' append initrd=/install.amd/initrd.gz --- quiet' > \"$extract\"; exit 0; fi\n"
                    "if [ -n \"$extract\" ]; then printf '%s' \"$FAKE_GRUB\" > \"$extract\"; exit 0; fi\n"
                    "[ -n \"$out\" ] && { : > \"$out\"; exit 0; }\n"
                    "exit 2\n",
                )
                executable(fake_bin / "dpkg-deb", "#!/bin/sh\nexit 0\n")
                executable(fake_bin / "sha256sum", "#!/bin/sh\nexit 0\n")
                bundle = root / "ubuntu-offline"
                bundle.mkdir()
                package = bundle / "qemu-guest-agent_fixture_amd64.deb"
                package.write_bytes(b"test package fixture")
                digest = hashlib.sha256(package.read_bytes()).hexdigest()
                (bundle / "SHA256SUMS").write_text(
                    f"{digest}  {package.name}\n", encoding="utf-8"
                )
                (bundle / "VERSIONS").write_text(
                    "ubuntu_release=24.04\narchitecture=amd64\n", encoding="utf-8"
                )
                base = root / "source.iso"
                base.write_bytes(b"verified fixture")
                environment = dict(
                    os.environ,
                    PATH=f"{fake_bin}:{os.environ['PATH']}",
                    HF_HIGH_ROOT=str(root / "high"),
                    HF_HIGH_UBUNTU_OFFLINE_BUNDLE=str(bundle),
                    FAKE_GRUB=grub,
                )
                subprocess.run(
                    [
                        "sh",
                        str(RECIPE / "scripts" / "prepare-unattended-iso.sh"),
                        str(base),
                        INSTANCE_ID,
                        flavor,
                    ],
                    check=True,
                    env=environment,
                    capture_output=True,
                    text=True,
                )
                instance = root / "high" / INSTANCE_ID
                self.assertTrue((instance / "unattended.iso").is_file())
                self.assertEqual(
                    stat.S_IMODE((instance / "ssh-password").stat().st_mode), 0o600
                )
                rendered_grub = (instance / "grub.cfg").read_text()
                self.assertIn("console=ttyS0", rendered_grub)
                if flavor == "ubuntu":
                    self.assertIn(
                        "autoinstall:",
                        (instance / "iso-payload/nocloud/user-data").read_text(),
                    )
                    self.assertIn(
                        "fallback: offline-install",
                        (instance / "iso-payload/nocloud/user-data").read_text(),
                    )
                    user_data = (instance / "iso-payload/nocloud/user-data").read_text()
                    self.assertNotIn("packages: [qemu-guest-agent", user_data)
                    self.assertIn("sha256sum -c SHA256SUMS", user_data)
                    self.assertIn("dpkg -i ./*.deb", user_data)
                    self.assertIn("shutdown: poweroff", user_data)
                if flavor == "debian":
                    preseed = (instance / "preseed.cfg").read_text()
                    self.assertIn("preseed/late_command", preseed)
                    self.assertIn("apt-setup/use_mirror boolean false", preseed)

    def test_arch_media_selects_bios_entry_before_pxe_and_rebuilds_rootfs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            xorriso_log = root / "xorriso.log"
            executable(
                fake_bin / "xorriso",
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$FAKE_XORRISO_LOG\"\n"
                "out=; extract=; source=\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  case $1 in\n"
                "    -extract) shift; source=$1; shift; extract=$1 ;;\n"
                "    -outdev) shift; out=$1 ;;\n"
                "  esac\n"
                "  shift\n"
                "done\n"
                "case $source in\n"
                "  /boot/syslinux)\n"
                "    mkdir -p \"$extract\"\n"
                "    printf '%s\\n' 'DEFAULT select' 'TIMEOUT 150' 'INCLUDE archiso_head.cfg' 'INCLUDE archiso_sys-linux.cfg' > \"$extract/archiso_sys.cfg\"\n"
                "    printf '%s\\n' 'SERIAL 0 115200' > \"$extract/archiso_head.cfg\"\n"
                "    printf '%s\\n' 'LABEL arch64_nbd' '  LINUX /arch/boot/x86_64/vmlinuz-linux' '  INITRD /arch/boot/x86_64/initramfs-linux.img' '  APPEND archisobasedir=arch archiso_nbd_srv=192.0.2.1' > \"$extract/archiso_pxe-linux.cfg\"\n"
                "    printf '%s\\n' 'LABEL arch64' '  LINUX /arch/boot/x86_64/vmlinuz-linux' '  INITRD /arch/boot/x86_64/initramfs-linux.img' '  APPEND archisobasedir=arch archisolabel=ARCH_202508' > \"$extract/archiso_sys-linux.cfg\"\n"
                "    exit 0 ;;\n"
                "  /arch/boot/x86_64/vmlinuz-linux|/arch/boot/x86_64/initramfs-linux.img|/EFI/BOOT/BOOTx64.EFI)\n"
                "    mkdir -p \"$(dirname \"$extract\")\"; : > \"$extract\"; exit 0 ;;\n"
                "  /arch/x86_64/airootfs.sfs)\n"
                "    printf '%s' 'fixture squashfs' > \"$extract\"; exit 0 ;;\n"
                "  /boot/grub/*) exit 9 ;;\n"
                "esac\n"
                "[ -n \"$out\" ] && { printf '%s' 'prepared ISO' > \"$out\"; exit 0; }\n"
                "exit 2\n",
            )
            repack_capture = root / "repacked-root"
            executable(
                fake_bin / "mksquashfs",
                "#!/bin/sh\n"
                "source=$1; image=$2\n"
                "dropin=\"$source/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf\"\n"
                "link=\"$source/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service\"\n"
                "[ -f \"$source/etc/from-original-rootfs\" ] || exit 19\n"
                "[ ! -e \"$source/etc_1\" ] || exit 20\n"
                "grep -F -- '--autologin root --keep-baud 115200,57600,38400,9600' \"$dropin\" >/dev/null || exit 20\n"
                "[ \"$(readlink \"$link\")\" = /usr/lib/systemd/system/serial-getty@.service ] || exit 21\n"
                "rm -rf \"$FAKE_REPACK_CAPTURE\"\n"
                "mkdir -p \"$FAKE_REPACK_CAPTURE\"\n"
                "cp -a \"$source/.\" \"$FAKE_REPACK_CAPTURE/\"\n"
                "printf '%s' 'prepared squashfs' > \"$image\"\n",
            )
            executable(
                fake_bin / "unsquashfs",
                "#!/bin/sh\n"
                "dest=; image=; selected=; list=false\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  case $1 in\n"
                "    -d) shift; dest=$1 ;;\n"
                "    -l) list=true ;;\n"
                "    -*) ;;\n"
                "    *) if [ -z \"$image\" ]; then image=$1; else selected=true; fi ;;\n"
                "  esac\n"
                "  shift\n"
                "done\n"
                "if [ \"$list\" = true ]; then\n"
                "  printf '%s\\n' squashfs-root squashfs-root/etc squashfs-root/etc/systemd\n"
                "  [ ! -e \"$FAKE_REPACK_CAPTURE/etc_1\" ] || printf '%s\\n' squashfs-root/etc_1\n"
                "  exit 0\n"
                "fi\n"
                "if [ -z \"$selected\" ]; then\n"
                "  mkdir -p \"$dest/etc\"\n"
                "  printf '%s\\n' preserved > \"$dest/etc/from-original-rootfs\"\n"
                "  chmod 0640 \"$dest/etc/from-original-rootfs\"\n"
                "  ln -s /usr/lib/original-target \"$dest/etc/original-link\"\n"
                "  exit 0\n"
                "fi\n"
                "mkdir -p \"$dest\"\n"
                "cp -a \"$FAKE_REPACK_CAPTURE/.\" \"$dest/\"\n",
            )
            executable(
                fake_bin / "sha512sum",
                "#!/bin/sh\nprintf '%0128d  %s\\n' 0 \"$1\"\n",
            )
            base = root / "archlinux-2025.08.01-x86_64.iso"
            base.write_bytes(b"verified Arch ISO fixture")
            base_digest = hashlib.sha256(base.read_bytes()).hexdigest()
            environment = dict(
                os.environ,
                PATH=f"{fake_bin}:{os.environ['PATH']}",
                HF_HIGH_ROOT=str(root / "high"),
                FAKE_XORRISO_LOG=str(xorriso_log),
                FAKE_REPACK_CAPTURE=str(repack_capture),
            )
            subprocess.run(
                [
                    "sh",
                    str(RECIPE / "scripts" / "prepare-unattended-iso.sh"),
                    str(base),
                    INSTANCE_ID,
                    "arch",
                ],
                check=True,
                env=environment,
                capture_output=True,
                text=True,
            )
            instance = root / "high" / INSTANCE_ID
            main = (instance / "boot-syslinux/archiso_sys.cfg").read_text()
            entry = (instance / "boot-syslinux/archiso_sys-linux.cfg").read_text()
            pxe = (instance / "boot-syslinux/archiso_pxe-linux.cfg").read_text()
            self.assertIn("DEFAULT arch64", main)
            self.assertNotIn("DEFAULT arch64_nbd", main)
            self.assertIn("PROMPT 0", main)
            self.assertIn("TIMEOUT 1", main)
            self.assertIn("SERIAL 0 115200", main)
            self.assertEqual(main.count("DEFAULT "), 1)
            self.assertEqual(main.count("TIMEOUT "), 1)
            self.assertIn("console=ttyS0,115200n8", entry)
            self.assertIn("console=tty0", entry)
            self.assertIn("archisobasedir=arch", entry)
            self.assertIn("LABEL arch64_nbd", pxe)
            self.assertIn("archiso_nbd_srv=192.0.2.1", pxe)
            self.assertNotIn("console=tty", pxe)
            calls = xorriso_log.read_text()
            self.assertIn("-extract /boot/syslinux", calls)
            self.assertIn("-extract /EFI/BOOT/BOOTx64.EFI", calls)
            self.assertIn("-extract /arch/x86_64/airootfs.sfs", calls)
            self.assertIn("-map", calls)
            self.assertIn("/arch/x86_64/airootfs.sfs", calls)
            self.assertIn("/arch/x86_64/airootfs.sha512", calls)
            self.assertIn("-boot_image any replay", calls)
            self.assertNotIn("/boot/grub", calls)
            self.assertTrue((instance / "unattended.iso").is_file())
            dropin = repack_capture / "etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf"
            self.assertIn("--autologin root", dropin.read_text())
            self.assertTrue((repack_capture / "etc/from-original-rootfs").is_file())
            self.assertEqual(
                stat.S_IMODE((repack_capture / "etc/from-original-rootfs").stat().st_mode),
                0o640,
            )
            self.assertTrue((repack_capture / "etc/original-link").is_symlink())
            self.assertEqual(
                os.readlink(repack_capture / "etc/original-link"),
                "/usr/lib/original-target",
            )
            self.assertFalse((repack_capture / "etc_1").exists())
            self.assertEqual(
                (instance / "unattended-arch.version").read_text().strip(),
                "arch-serial-getty-v3",
            )
            self.assertEqual(hashlib.sha256(base.read_bytes()).hexdigest(), base_digest)

            calls_before_retry = xorriso_log.read_text()
            subprocess.run(
                [
                    "sh",
                    str(RECIPE / "scripts" / "prepare-unattended-iso.sh"),
                    str(base),
                    INSTANCE_ID,
                    "arch",
                ],
                check=True,
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(xorriso_log.read_text(), calls_before_retry)

    @unittest.skipUnless(shutil.which("expect"), "expect is required for Arch console tests")
    def test_arch_console_accepts_ansi_prompt_and_hides_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            executable(
                fake_bin / "virsh",
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "def emit(value):\n"
                "    sys.stdout.write(value); sys.stdout.flush()\n"
                "emit('Connected to domain fixture-vm\\r\\n')\n"
                "if sys.stdin.readline().strip(): raise SystemExit(10)\n"
                "emit('root@archiso ~ # \\x1b[?2004h')\n"
                "if not sys.stdin.readline().startswith('stty -echo'): raise SystemExit(11)\n"
                "emit('HF_SERIAL_READY\\r\\nroot@archiso ~ # \\x1b[?2004h')\n"
                "if not sys.stdin.readline().startswith('rm -f '): raise SystemExit(12)\n"
                "emit('root@archiso ~ # \\x1b[?2004h')\n"
                "chunks = 0\n"
                "while True:\n"
                "    line = sys.stdin.readline()\n"
                "    if line.startswith(\"printf '%s' '\"):\n"
                "        chunks += 1; emit('root@archiso ~ # \\x1b[?2004h'); continue\n"
                "    if line.startswith('base64 -d '): break\n"
                "    raise SystemExit(13)\n"
                "if chunks < 2: raise SystemExit(14)\n"
                "emit('installing offline\\r\\nHF_INSTALL_COMPLETE\\r\\n')\n",
            )
            payload_value = base64.b64encode(b"fixture" * 600).decode("ascii")
            payload = root / "payload.b64"
            payload.write_text(payload_value, encoding="ascii")
            payload.chmod(0o600)
            console_log = root / "console.log"
            console_log.write_text("", encoding="utf-8")
            console_log.chmod(0o600)
            completed = subprocess.run(
                [
                    shutil.which("expect"),
                    str(RECIPE / "scripts" / "arch-console.exp"),
                    "fixture-vm",
                    str(payload),
                    str(console_log),
                ],
                check=False,
                env=dict(
                    os.environ,
                    PATH=f"{fake_bin}:{os.environ['PATH']}",
                    HF_HIGH_INSTALL_TIMEOUT_SECONDS="10",
                    HF_HIGH_ARCH_BOOT_TIMEOUT_SECONDS="3",
                ),
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            diagnostic = console_log.read_text(encoding="utf-8")
            self.assertIn("Connected to domain", diagnostic)
            self.assertIn("root@archiso", diagnostic)
            self.assertIn("<redacted-payload>", diagnostic)
            self.assertNotIn(payload_value, diagnostic)
            self.assertNotIn(payload_value[:768], diagnostic)
            self.assertEqual(stat.S_IMODE(console_log.stat().st_mode), 0o600)

    @unittest.skipUnless(shutil.which("expect"), "expect is required for Arch console tests")
    def test_arch_console_root_wait_has_diagnostic_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            executable(
                fake_bin / "virsh",
                "#!/usr/bin/env python3\n"
                "import sys, time\n"
                "sys.stdout.write('Booting ArchISO without login prompt\\r\\n'); sys.stdout.flush()\n"
                "time.sleep(10)\n",
            )
            payload = root / "payload.b64"
            payload.write_text("Zml4dHVyZQ==", encoding="ascii")
            console_log = root / "console.log"
            console_log.write_text("", encoding="utf-8")
            completed = subprocess.run(
                [
                    shutil.which("expect"),
                    str(RECIPE / "scripts" / "arch-console.exp"),
                    "fixture-vm",
                    str(payload),
                    str(console_log),
                ],
                check=False,
                env=dict(
                    os.environ,
                    PATH=f"{fake_bin}:{os.environ['PATH']}",
                    HF_HIGH_INSTALL_TIMEOUT_SECONDS="10",
                    HF_HIGH_ARCH_BOOT_TIMEOUT_SECONDS="1",
                ),
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(completed.returncode, 3)
            self.assertIn("code=ARCH_SERIAL_ROOT_TIMEOUT", completed.stderr)
            self.assertIn("Booting ArchISO", console_log.read_text(encoding="utf-8"))

    def test_ubuntu_finalizer_requires_disk_boot_and_full_guest_readiness(self):
        finalizer = (RECIPE / "scripts" / "finalize-linux-install.sh").read_text()
        self.assertIn("wait_for_installer_poweroff", finalizer)
        self.assertIn("disk_marker_ready", finalizer)
        self.assertIn('change-media "$vm_name" "$target" --eject --config', finalizer)
        self.assertIn('"guest-ping"', finalizer)
        self.assertIn('"qemu-guest-agent.service"', finalizer)
        self.assertIn('"high-telemetry.service"', finalizer)
        self.assertIn('["-Fxq", "installed", "/etc/honeyforge-installed"]', finalizer)
        self.assertIn('banner.startswith(b"SSH-2.0-")', finalizer)
        self.assertLess(
            finalizer.index('change-media "$vm_name" "$target" --eject --config'),
            finalizer.rindex(': > "$instance_dir/installed-disk-verified"'),
        )

    def test_ubuntu_finalization_is_idempotent_with_empty_cdrom(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            high_root = root / "high"
            instance = high_root / INSTANCE_ID
            instance.mkdir(parents=True)
            (instance / "disk.qcow2").write_bytes(b"installed disk fixture")
            state = root / "domain-state"
            state.write_text("shut off\n", encoding="utf-8")
            log = root / "virsh.log"
            probes = root / "cdrom-probes"
            probes.write_text("0\n", encoding="utf-8")
            executable(
                fake_bin / "virsh",
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$FAKE_VIRSH_LOG\"\n"
                "case $1 in\n"
                "  domblklist)\n"
                "    count=$(cat \"$FAKE_CDROM_PROBES\"); count=$((count + 1)); printf '%s\\n' \"$count\" > \"$FAKE_CDROM_PROBES\"\n"
                "    if [ \"$count\" -eq 1 ]; then source=/fixture/installer.iso; else source=-; fi\n"
                "    printf '%s\\n' \"file cdrom hda $source\" 'file disk vda /fixture/disk.qcow2' ;;\n"
                "  domstate) cat \"$FAKE_VM_STATE\" ;;\n"
                "  start) printf '%s\\n' running > \"$FAKE_VM_STATE\" ;;\n"
                "  domifaddr) printf '%s\\n' 'vnet0 52:54:00:00:00:01 ipv4 192.0.2.10/24' ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n",
            )
            executable(fake_bin / "virt-cat", "#!/bin/sh\nprintf '%s\\n' installed\n")
            executable(fake_bin / "timeout", "#!/bin/sh\nshift\nexec \"$@\"\n")
            # guest_checks is separately asserted above; this test isolates finalization state.
            executable(fake_bin / "python3", "#!/bin/sh\nexit 0\n")
            environment = dict(
                os.environ,
                PATH=f"{fake_bin}:{os.environ['PATH']}",
                HF_HIGH_ROOT=str(high_root),
                FAKE_VM_STATE=str(state),
                FAKE_VIRSH_LOG=str(log),
                FAKE_CDROM_PROBES=str(probes),
            )
            command = [
                "sh",
                str(RECIPE / "scripts" / "finalize-linux-install.sh"),
                INSTANCE_ID,
                "ubuntu",
            ]
            subprocess.run(
                command, check=True, env=environment, capture_output=True, text=True
            )
            subprocess.run(
                command, check=True, env=environment, capture_output=True, text=True
            )
            self.assertTrue((instance / "installed-disk-verified").is_file())
            calls = log.read_text(encoding="utf-8")
            self.assertNotIn("change-media", calls)
            self.assertEqual(calls.count("start hf-high-"), 1)
            self.assertTrue((instance / "disk.qcow2").is_file())

    def test_ubuntu_finalizer_does_not_hide_real_eject_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            high_root = root / "high"
            instance = high_root / INSTANCE_ID
            instance.mkdir(parents=True)
            (instance / "disk.qcow2").write_bytes(b"installed disk fixture")
            executable(
                fake_bin / "virsh",
                "#!/bin/sh\n"
                "case $1 in\n"
                "  domblklist) printf '%s\\n' 'file cdrom hda /fixture/installer.iso' 'file disk vda /fixture/disk.qcow2' ;;\n"
                "  domstate) printf '%s\\n' 'shut off' ;;\n"
                "  change-media) exit 1 ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n",
            )
            executable(fake_bin / "virt-cat", "#!/bin/sh\nprintf '%s\\n' installed\n")
            executable(fake_bin / "timeout", "#!/bin/sh\nshift\nexec \"$@\"\n")
            executable(fake_bin / "python3", "#!/bin/sh\nexit 0\n")
            completed = subprocess.run(
                [
                    "sh",
                    str(RECIPE / "scripts" / "finalize-linux-install.sh"),
                    INSTANCE_ID,
                    "ubuntu",
                ],
                check=False,
                env=dict(
                    os.environ,
                    PATH=f"{fake_bin}:{os.environ['PATH']}",
                    HF_HIGH_ROOT=str(high_root),
                ),
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("INSTALL_MEDIA_EJECT_FAILED", completed.stderr)
            self.assertFalse((instance / "installed-disk-verified").exists())


if __name__ == "__main__":
    unittest.main()
