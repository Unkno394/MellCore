#!/usr/bin/env python3
"""Exercise response ordering with mocks only; never call host Docker/nft/systemd."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[2] / "crates/hf-agent/src/emergency.sh"
MOCK = '''#!/bin/sh
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$HF_TEST_LOG"
case "$name" in
  stat) case "$2" in %u) echo 0;; %a) echo 600;; esac ;;
  docker) [ "$1" != ps ] || echo abcdef123456 ;;
  nft) if [ "$1" = -f ]; then cat > "$HF_TEST_RULES"; exit "${HF_TEST_NFT_FAILURE:-0}"; fi ;;
  systemctl) exit "${HF_TEST_POWEROFF_FAILURE:-0}" ;;
esac
exit 0
'''


class EmergencyTest(unittest.TestCase):
    def run_response(self, armed=True, nft_failure=0, poweroff_failure=0, symlink=False):
        with tempfile.TemporaryDirectory(prefix="hf-emergency-test-") as temporary:
            root = Path(temporary)
            marker = root / "confirmed-escape"
            marker.write_text("10000000-0000-4000-8000-000000000001\n"
                              "20000000-0000-4000-8000-000000000001\n"
                              f"armed={int(armed)}\n")
            marker.chmod(0o600)
            if symlink:
                real = root / "real"
                marker.rename(real)
                marker.symlink_to(real)
            script = root / "emergency.sh"
            # Only the marker path is redirected; all response commands are mocks.
            script.write_text(SOURCE.read_text().replace(
                "/var/lib/honeyforge/security/confirmed-escape", str(marker)))
            mocks = root / "bin"
            mocks.mkdir()
            for name in ("docker", "nft", "systemctl", "logger", "sync", "stat"):
                executable = mocks / name
                executable.write_text(MOCK)
                executable.chmod(0o700)
            log = root / "commands"
            rules = root / "rules"
            env = dict(os.environ, PATH=f"{mocks}:/usr/bin:/bin", HF_TEST_LOG=str(log),
                       HF_TEST_RULES=str(rules), HF_TEST_NFT_FAILURE=str(nft_failure),
                       HF_TEST_POWEROFF_FAILURE=str(poweroff_failure))
            result = subprocess.run(["/bin/sh", str(script), str(marker)], env=env,
                                    capture_output=True, text=True, timeout=10)
            return (result.returncode, log.read_text() if log.exists() else "",
                    rules.read_text() if rules.exists() else "")

    def test_unarmed_never_isolates_or_powers_off(self):
        code, log, _ = self.run_response(armed=False)
        self.assertNotEqual(code, 0)
        for name in ("docker", "nft", "systemctl"):
            self.assertNotIn(name, log)

    def test_symlink_marker_is_rejected(self):
        code, log, _ = self.run_response(symlink=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(log, "")

    def test_armed_order_and_project_scope(self):
        code, log, rules = self.run_response()
        self.assertEqual(code, 0, log)
        self.assertIn("label=com.docker.compose.project=hf-10000000000040008000000000000001", log)
        self.assertLess(log.index("docker stop"), log.index("nft -f"))
        self.assertLess(log.index("nft -f"), log.index("systemctl poweroff"))
        self.assertEqual(rules.count("policy drop"), 3)
        self.assertNotIn("flush ruleset", rules)

    def test_firewall_failure_still_attempts_poweroff(self):
        code, log, _ = self.run_response(nft_failure=1)
        self.assertEqual(code, 0)
        self.assertIn("network isolation failed", log)
        self.assertIn("systemctl poweroff", log)

    def test_poweroff_failure_is_reported_for_service_retry(self):
        code, log, _ = self.run_response(poweroff_failure=1)
        self.assertNotEqual(code, 0)
        self.assertIn("poweroff failed", log)


if __name__ == "__main__":
    unittest.main()
