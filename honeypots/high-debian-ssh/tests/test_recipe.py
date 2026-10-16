import os
import pathlib
import stat
import subprocess
import tempfile
import unittest


RECIPE = pathlib.Path(__file__).resolve().parents[1]


class DebianRecipeTests(unittest.TestCase):
    def test_scripts_are_valid_shell(self):
        for script in (RECIPE / "scripts").glob("*.sh"):
            subprocess.run(["sh", "-n", str(script)], check=True)

    def test_managed_image_uses_official_https_manifest_and_rechecks_cache(self):
        script = (RECIPE / "scripts" / "download-base-image.sh").read_text()
        self.assertIn("https://cloud.debian.org/images/cloud/bookworm/latest", script)
        self.assertIn("SHA512SUMS", script)
        self.assertIn("sha512sum", script)
        self.assertIn("qemu-img check", script)
        self.assertIn("refusing to replace a possible live backing image", script)

    def test_cloud_init_enables_ssh_and_existing_telemetry_sensor(self):
        user_data = (RECIPE / "cloud-init" / "user-data").read_text()
        self.assertIn("@@ANALYST_PASSWORD_HASH@@", user_data)
        self.assertIn("systemctl enable --now ssh", user_data)
        self.assertIn("honeyforge-high-telemetry.service", user_data)
        launch = (RECIPE / "scripts" / "launch.sh").read_text()
        self.assertIn("network=hf-high-isolated", launch)
        self.assertIn("org.honeyforge.telemetry.0", launch)
        self.assertIn("setfacl", launch)

    def test_debian_uses_v1_mac_mapping_and_virtio_nocloud_seed(self):
        network = (RECIPE / "cloud-init" / "network-config").read_text()
        self.assertIn("version: 1", network)
        self.assertIn("mac_address: '@@MAC_ADDRESS@@'", network)
        self.assertIn("type: dhcp4", network)

        launch = (RECIPE / "scripts" / "launch.sh").read_text()
        self.assertIn("format=raw,device=disk,bus=virtio,readonly=on", launch)
        self.assertIn("network=hf-high-isolated,model=virtio,mac=$guest_mac", launch)

    def test_overlay_renders_deterministic_mac_without_modifying_base(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            for name, body in {
                "qemu-img": '#!/bin/sh\n: > "$8"\n',
                "cloud-localds": '#!/bin/sh\nprintf "%s\\n" "$@" > "$HF_TEST_CLOUD_ARGS"\n: > "$2"\n',
                "virt-customize": '#!/bin/sh\nprintf "%s\\n" "$@" > "$HF_TEST_VIRT_ARGS"\n',
            }.items():
                tool = tools / name
                tool.write_text(body)
                tool.chmod(tool.stat().st_mode | stat.S_IXUSR)

            base = root / "verified-base.qcow2"
            base.write_bytes(b"immutable Debian base")
            instance = root / "instance"
            cloud_args = root / "cloud-localds.args"
            virt_args = root / "virt-customize.args"
            env = os.environ.copy()
            env["PATH"] = f"{tools}:{env['PATH']}"
            env["HF_TEST_CLOUD_ARGS"] = str(cloud_args)
            env["HF_TEST_VIRT_ARGS"] = str(virt_args)
            subprocess.run(
                [
                    "sh",
                    str(RECIPE / "scripts" / "create-overlay.sh"),
                    str(base),
                    str(instance),
                    "11111111-2222-4333-8444-555555555555",
                ],
                check=True,
                env=env,
                capture_output=True,
                text=True,
            )

            self.assertEqual(base.read_bytes(), b"immutable Debian base")
            self.assertEqual((instance / "mac-address").read_text().strip(), "52:54:11:11:11:11")
            rendered = (instance / "network-config").read_text()
            self.assertIn("mac_address: '52:54:11:11:11:11'", rendered)
            self.assertNotIn("@@", rendered)
            self.assertIn(
                f"--network-config={instance / 'network-config'}",
                cloud_args.read_text().splitlines(),
            )
            customization = virt_args.read_text().splitlines()
            self.assertIn(str(instance / "disk.qcow2"), customization)
            self.assertNotIn(str(base), customization)
            self.assertIn("--network", customization)
            self.assertIn("qemu-guest-agent,auditd", customization)

    def test_guest_agent_and_audit_telemetry_are_required_at_first_boot(self):
        user_data = (RECIPE / "cloud-init" / "user-data").read_text()
        self.assertIn("test -x /usr/sbin/qemu-ga", user_data)
        self.assertIn("systemctl restart qemu-guest-agent.service", user_data)
        self.assertIn("systemctl is-active --quiet qemu-guest-agent.service", user_data)
        self.assertIn("test -x /usr/sbin/auditd", user_data)
        self.assertIn("augenrules --load", user_data)
        self.assertIn("systemctl enable --now auditd", user_data)

    def test_repeated_publication_keeps_existing_dnat(self):
        wrapper = (RECIPE / "scripts" / "publish-service.sh").read_text()
        self.assertLess(wrapper.index("check-publication.sh"), wrapper.index("publish-ssh.sh"))
        self.assertIn("exit 0", wrapper)

    def test_debian_opts_into_distinct_dhcp_timeout_diagnostic(self):
        wrapper = (RECIPE / "scripts" / "publish-service.sh").read_text()
        shared = (RECIPE.parent / "high-ubuntu-ssh" / "scripts" / "publish-ssh.sh").read_text()
        self.assertIn("HF_HIGH_DIAGNOSE_DHCP=1", wrapper)
        self.assertIn('join("dhcp-timeout")', (RECIPE.parents[1] / "crates/hf-agent/src/sandbox.rs").read_text())
        self.assertIn('dhcp_failure_marker="$root_dir/$instance_id/dhcp-timeout"', shared)


if __name__ == "__main__":
    unittest.main()
