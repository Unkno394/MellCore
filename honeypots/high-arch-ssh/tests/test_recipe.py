import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


RECIPE = Path(__file__).resolve().parents[1]
DOWNLOAD = RECIPE / "scripts" / "download-base-image.sh"


class ArchImageDownloadTests(unittest.TestCase):
    def make_tools(self, directory: Path) -> None:
        qemu_img = directory / "qemu-img"
        qemu_img.write_text("#!/bin/sh\nprintf '%s\\n' '{\"format\":\"qcow2\"}'\n")
        qemu_img.chmod(qemu_img.stat().st_mode | stat.S_IXUSR)

    def run_downloader(self, destination: Path, payload: bytes, expected: str):
        tools = destination.parent / "tools"
        tools.mkdir(exist_ok=True)
        self.make_tools(tools)
        source = destination.parent / "source.qcow2"
        source.write_bytes(payload)
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{tools}:{env['PATH']}",
                "HF_HIGH_ARCH_IMAGE_URL": f"https://example.invalid/{source.name}",
                "HF_HIGH_ARCH_IMAGE_SHA256": expected,
            }
        )
        # Avoid network access: emulate curl by copying the local fixture to its --output path.
        curl = tools / "curl"
        curl.write_text(
            "#!/bin/sh\n"
            "while [ $# -gt 0 ]; do\n"
            "  if [ \"$1\" = --output ]; then out=$2; shift 2; else shift; fi\n"
            "done\n"
            f"cp '{source}' \"$out\"\n"
        )
        curl.chmod(curl.stat().st_mode | stat.S_IXUSR)
        return subprocess.run(
            ["sh", str(DOWNLOAD), str(destination)],
            env=env,
            text=True,
            capture_output=True,
        )

    def test_download_is_verified_and_cached_copy_is_reverified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "arch.qcow2"
            payload = b"verified qcow2 fixture"
            expected = hashlib.sha256(payload).hexdigest()
            first = self.run_downloader(destination, payload, expected)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(destination.read_bytes(), payload)

            destination.write_bytes(b"corrupt cache")
            second = self.run_downloader(destination, payload, expected)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(destination.read_bytes(), b"corrupt cache")
            self.assertIn("refusing to replace", second.stderr)

    def test_non_https_source_is_rejected_before_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "arch.qcow2"
            tools = root / "tools"
            tools.mkdir()
            self.make_tools(tools)
            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{tools}:{env['PATH']}",
                    "HF_HIGH_ARCH_IMAGE_URL": "http://example.invalid/arch.qcow2",
                    "HF_HIGH_ARCH_IMAGE_SHA256": "0" * 64,
                }
            )
            result = subprocess.run(
                ["sh", str(DOWNLOAD), str(destination)],
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must use HTTPS", result.stderr)


class ArchCloudInitTests(unittest.TestCase):
    def test_network_matches_arch_boxes_eth0_and_disables_ipv6(self):
        network = (RECIPE / "cloud-init" / "network-config").read_text()
        self.assertIn('name: "e*"', network)
        self.assertIn("dhcp4: true", network)
        self.assertIn("dhcp6: false", network)
        self.assertIn("accept-ra: false", network)

    def test_template_has_unique_credentials_ssh_and_sensor_startup(self):
        user_data = (RECIPE / "cloud-init" / "user-data").read_text()
        self.assertIn("@@ANALYST_PASSWORD_HASH@@", user_data)
        self.assertIn("systemctl enable --now sshd", user_data)
        self.assertIn("systemctl enable --now honeyforge-high-telemetry.service", user_data)
        self.assertIn("org.honeyforge.telemetry.0", (RECIPE / "scripts" / "launch.sh").read_text())

    def test_launch_grants_qemu_only_targeted_acl_access(self):
        launch = (RECIPE / "scripts" / "launch.sh").read_text()
        self.assertIn('libvirt_user=${HF_HIGH_LIBVIRT_USER:-libvirt-qemu}', launch)
        acl_lines = "\n".join(line for line in launch.splitlines() if "setfacl" in line)
        self.assertIn('"$instance_dir/disk.qcow2"', acl_lines)
        self.assertIn('"$instance_dir/seed.iso"', acl_lines)
        self.assertNotIn('"$instance_dir/ssh-password"', acl_lines)

    def test_pinned_default_checksum_is_real_sha256(self):
        script = DOWNLOAD.read_text()
        marker = "default_sha256='"
        checksum = script.split(marker, 1)[1].split("'", 1)[0]
        self.assertEqual(len(checksum), 64)
        int(checksum, 16)
        self.assertIn("/images/v20261001.604814/", script)


if __name__ == "__main__":
    unittest.main()
