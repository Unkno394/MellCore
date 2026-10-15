import pathlib
import hashlib
import os
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
        self.assertIn('--cdrom "$install_iso" --boot cdrom,hd', launch)
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
        self.assertIn("--boot cdrom,hd", launch)
        self.assertIn('change-media "$vm_name"', finalizer)
        self.assertIn('virsh start "$vm_name"', finalizer)
        self.assertIn("installed-disk-verified", finalizer)
        self.assertIn("virt-cat", arch)
        self.assertIn("installed-disk-verified", arch)
        guest = (RECIPE / "scripts" / "arch-guest-install.sh").read_text()
        self.assertNotIn("pacstrap", guest)
        self.assertIn("INSTALL_MEDIA_COMPONENT_MISSING", guest)
        self.assertIn("cp -a", guest)

    def test_installation_is_restartable_and_bounded(self):
        launch = (RECIPE / "scripts" / "launch-iso.sh").read_text()
        arch = (RECIPE / "scripts" / "install-arch.sh").read_text()
        self.assertNotIn("virsh undefine", launch)
        self.assertIn("HF_HIGH_INSTALL_TIMEOUT_SECONDS", arch)
        self.assertIn("install-started", arch)

    def test_unattended_media_is_generated_per_instance(self):
        grub_by_flavor = {
            "ubuntu": "menuentry x {\n linux /casper/vmlinuz ---\n}\n",
            "debian": "menuentry x {\n linux /install.amd/vmlinuz --- quiet\n}\n",
            "arch": "menuentry x {\n linux /arch/boot/x86_64/vmlinuz-linux archisobasedir=arch\n}\n",
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
                    "if [ \"$source\" = /syslinux ]; then mkdir -p \"$extract\"; printf '%s\\n' ' APPEND archisobasedir=arch' > \"$extract/arch.cfg\"; exit 0; fi\n"
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
