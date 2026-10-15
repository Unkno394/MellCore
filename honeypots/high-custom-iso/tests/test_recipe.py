import pathlib
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
        self.assertIn("network=hf-high-isolated", launch)
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
                base = root / "source.iso"
                base.write_bytes(b"verified fixture")
                environment = dict(
                    os.environ,
                    PATH=f"{fake_bin}:{os.environ['PATH']}",
                    HF_HIGH_ROOT=str(root / "high"),
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
                if flavor == "debian":
                    self.assertIn("preseed/late_command", (instance / "preseed.cfg").read_text())


if __name__ == "__main__":
    unittest.main()
