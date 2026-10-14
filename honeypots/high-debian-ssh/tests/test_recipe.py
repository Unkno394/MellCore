import pathlib
import subprocess
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


if __name__ == "__main__":
    unittest.main()
