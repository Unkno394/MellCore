import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


RECIPE = Path(__file__).resolve().parents[1]
SCRIPTS = RECIPE / "scripts"
INSTANCE_ID = "11111111-2222-4333-8444-555555555555"


def executable(path, body):
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class PreparedWindowsRecipeTests(unittest.TestCase):
    def test_local_base_is_reverified_as_qcow2_without_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            executable(
                fake_bin / "qemu-img",
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "  info) if [ -n \"${FAKE_BACKING:-}\" ]; then printf '%s\\n' '{\"format\":\"qcow2\",\"backing-filename\":\"parent.qcow2\"}'; else printf '%s\\n' '{\"format\":\"qcow2\",\"virtual-size\":42949672960}'; fi ;;\n"
                "  check) exit 0 ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n",
            )
            image = root / "windows-server-prepared.qcow2"
            image.write_bytes(b"prepared image")
            checksum = hashlib.sha256(image.read_bytes()).hexdigest()
            image.with_suffix(image.suffix + ".sha256").write_text(checksum + "  image\n")
            environment = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}")

            subprocess.run(
                ["sh", str(SCRIPTS / "verify-prepared-image.sh"), str(image)],
                check=True,
                env=environment,
                capture_output=True,
                text=True,
            )
            with_backing = dict(environment, FAKE_BACKING="1")
            failed = subprocess.run(
                ["sh", str(SCRIPTS / "verify-prepared-image.sh"), str(image)],
                env=with_backing,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(failed.returncode, 0)
            original = image.read_bytes()
            image.with_suffix(image.suffix + ".sha256").write_text("0" * 64 + "\n")
            failed = subprocess.run(
                ["sh", str(SCRIPTS / "verify-prepared-image.sh"), str(image)],
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(image.read_bytes(), original)

    def test_overlay_and_openstack_config_drive_have_unique_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            executable(
                fake_bin / "qemu-img",
                "#!/bin/sh\n"
                "if [ \"$1\" = info ]; then printf '%s\\n' '{\"format\":\"qcow2\",\"virtual-size\":42949672960}'; exit; fi\n"
                "[ \"$1\" = create ] || exit 2\n"
                ": > \"$8\"\n"
                "printf '%s\\n' \"$*\" > \"$QEMU_ARGS\"\n",
            )
            executable(
                fake_bin / "xorriso",
                "#!/bin/sh\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = -o ]; then shift; : > \"$1\"; exit 0; fi\n"
                "  shift\n"
                "done\n"
                "exit 2\n",
            )
            base = root / "base.qcow2"
            base.write_bytes(b"base")
            instance = root / "instance"
            args_log = root / "qemu-args"
            environment = dict(
                os.environ,
                PATH=f"{fake_bin}:{os.environ['PATH']}",
                QEMU_ARGS=str(args_log),
            )
            subprocess.run(
                [
                    "sh",
                    str(SCRIPTS / "create-prepared-overlay.sh"),
                    str(base),
                    str(instance),
                    INSTANCE_ID,
                ],
                check=True,
                env=environment,
                capture_output=True,
                text=True,
            )

            metadata = json.loads(
                (instance / "config-drive/openstack/latest/meta_data.json").read_text()
            )
            password = (instance / "rdp-password").read_text().strip()
            self.assertEqual(metadata["uuid"], INSTANCE_ID)
            self.assertEqual(metadata["hostname"], "hf-111111112222")
            self.assertEqual(metadata["meta"]["admin_username"], "hfadmin")
            self.assertEqual(metadata["meta"]["admin_pass"], password)
            self.assertGreaterEqual(len(password), 24)
            self.assertEqual(stat.S_IMODE((instance / "rdp-password").stat().st_mode), 0o600)
            self.assertIn(f"-b {base}", args_log.read_text())
            self.assertTrue((instance / "disk.qcow2").is_file())
            self.assertTrue((instance / "config-drive.iso").is_file())

    def test_prepared_launch_is_import_only_and_never_publishes_rdp(self):
        launch = (SCRIPTS / "launch-prepared.sh").read_text(encoding="utf-8")
        discover = (SCRIPTS / "discover-rdp.sh").read_text(encoding="utf-8")
        self.assertIn("--import", launch)
        self.assertIn("bus=virtio", launch)
        self.assertNotIn("publish-service.sh", launch + discover)
        self.assertNotIn("DNAT", launch + discover)
        self.assertNotIn("external-ssh-port\" >", launch + discover)
        self.assertIn("listen=127.0.0.1", launch)

    def test_missing_prepared_image_invokes_builder_with_approved_catalog(self):
        ensure = (SCRIPTS / "ensure-prepared-image.sh").read_text(encoding="utf-8")
        self.assertIn("/usr/local/lib/honeyforge/hf-image-builder/hf-image-builder", ensure)
        self.assertIn("/etc/honeyforge/image-sources/windows-server-2022.json", ensure)
        self.assertIn('"$builder" --catalog "$catalog" build', ensure)
        self.assertIn("incomplete prepared Windows image publication", ensure)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            image = root / "windows-server-prepared.qcow2"
            catalog = root / "catalog.json"
            catalog.write_text("{}\n")
            arguments = root / "builder.args"
            executable(
                fake_bin / "qemu-img",
                "#!/bin/sh\n"
                "[ \"$1\" = info ] && { printf '%s\\n' '{\"format\":\"qcow2\"}'; exit; }\n"
                "[ \"$1\" = check ] && exit 0\n"
                "exit 2\n",
            )
            executable(
                root / "builder",
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" > \"$HF_TEST_ARGS\"\n"
                "printf prepared > \"$HF_TEST_IMAGE\"\n"
                "sha256sum \"$HF_TEST_IMAGE\" > \"$HF_TEST_IMAGE.sha256\"\n",
            )
            environment = dict(
                os.environ,
                PATH=f"{fake_bin}:{os.environ['PATH']}",
                HF_HIGH_IMAGE_BUILDER=str(root / "builder"),
                HF_HIGH_WINDOWS_SOURCE_CATALOG=str(catalog),
                HF_TEST_ARGS=str(arguments),
                HF_TEST_IMAGE=str(image),
            )
            subprocess.run(
                ["sh", str(SCRIPTS / "ensure-prepared-image.sh"), str(image)],
                check=True,
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertEqual(arguments.read_text().strip(), f"--catalog {catalog} build")

    def test_isolation_probe_rejects_an_rdp_dnat_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instance = root / INSTANCE_ID
            instance.mkdir()
            (instance / "guest-ip").write_text("192.168.250.123\n")
            fake_bin = root / "bin"
            fake_bin.mkdir()
            executable(fake_bin / "iptables", "#!/bin/sh\nexit 0\n")
            executable(
                fake_bin / "iptables-save",
                "#!/bin/sh\n[ -n \"${FAKE_DNAT:-}\" ] && printf '%s\\n' '-A HF_HIGH_DNAT -p tcp -j DNAT --to-destination 192.168.250.123:3389'\n",
            )
            environment = dict(
                os.environ,
                PATH=f"{fake_bin}:{os.environ['PATH']}",
                HF_HIGH_ROOT=str(root),
            )
            command = ["sh", str(SCRIPTS / "check-rdp-isolated.sh"), INSTANCE_ID]
            subprocess.run(command, check=True, env=environment, capture_output=True, text=True)
            environment["FAKE_DNAT"] = "1"
            failed = subprocess.run(command, env=environment, capture_output=True, text=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("unexpected DNAT", failed.stderr)

    def test_all_recipe_scripts_are_valid_shell(self):
        for script in SCRIPTS.glob("*.sh"):
            subprocess.run(["sh", "-n", str(script)], check=True)


if __name__ == "__main__":
    unittest.main()
