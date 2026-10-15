import pathlib
import subprocess
import unittest


RECIPE = pathlib.Path(__file__).resolve().parents[1]


class CustomIsoRecipeTests(unittest.TestCase):
    def test_scripts_are_valid_shell(self):
        for script in (RECIPE / "scripts").glob("*.sh"):
            subprocess.run(["sh", "-n", str(script)], check=True)

    def test_installer_is_isolated_and_has_no_publication(self):
        launch = (RECIPE / "scripts" / "launch-iso.sh").read_text()
        check = (RECIPE / "scripts" / "check-ssh-isolated.sh").read_text()
        self.assertIn("network=hf-high-isolated", launch)
        self.assertIn("spice,listen=127.0.0.1", launch)
        self.assertNotIn("publish-ssh", launch)
        self.assertIn("unexpected DNAT publication", check)
        self.assertIn("HF_HIGH_INPUT_CHAIN", check)
        self.assertIn("ESTABLISHED,RELATED", check)


if __name__ == "__main__":
    unittest.main()
