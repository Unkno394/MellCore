import base64
import json
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


RECIPE = Path(__file__).resolve().parents[1]
SCRIPTS = RECIPE / "scripts"
ARCH_RECIPE = RECIPE.parent / "high-arch-ssh"
WINDOWS_RECIPE = RECIPE.parent / "high-windows-rdp"


def executable(path, body):
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def embedded_files(user_data):
    result = {}
    current = None
    for line in user_data.splitlines():
        stripped = line.strip()
        if stripped.startswith("- path: "):
            current = stripped.removeprefix("- path: ")
        elif current and stripped.startswith("content: "):
            encoded = stripped.removeprefix("content: ").strip("'")
            result[current] = base64.b64decode(encoded)
            current = None
    return result


class CloudInitGenerationTests(unittest.TestCase):
    def test_generated_cloud_init_contains_exact_valid_guest_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            executable(
                fake_bin / "qemu-img",
                "#!/bin/sh\n: > \"$8\"\n",
            )
            executable(
                fake_bin / "cloud-localds",
                "#!/bin/sh\nshift\n: > \"$1\"\n",
            )
            base_image = root / "base.qcow2"
            base_image.write_bytes(b"test base")
            instance = root / "instance"
            instance_id = "11111111-2222-4333-8444-555555555555"
            environment = dict(os.environ)
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

            subprocess.run(
                ["sh", str(SCRIPTS / "create-overlay.sh"), str(base_image), str(instance), instance_id],
                check=True,
                env=environment,
                capture_output=True,
                text=True,
            )

            user_data = (instance / "user-data").read_text(encoding="utf-8")
            self.assertNotIn("@@", user_data)
            self.assertNotIn("plain_text_passwd", user_data)
            password = (instance / "ssh-password").read_text(encoding="utf-8").strip()
            self.assertGreaterEqual(len(password), 24)
            self.assertNotIn(password, user_data)
            self.assertIn("passwd: '$6$", user_data)
            self.assertEqual(stat.S_IMODE((instance / "ssh-password").stat().st_mode), 0o600)
            self.assertIn(f"instance-id: hf-high-{instance_id}", (instance / "meta-data").read_text())

            files = embedded_files(user_data)
            expected = {
                "/usr/local/lib/honeyforge/high-telemetry-sensor": RECIPE / "guest/high_telemetry_sensor.py",
                "/usr/local/lib/honeyforge/high_telemetry_audit.py": RECIPE / "guest/high_telemetry_audit.py",
                "/etc/systemd/system/honeyforge-high-telemetry.service": RECIPE / "guest/high-telemetry.service",
                "/etc/audit/rules.d/90-honeyforge.rules": RECIPE / "guest/90-honeyforge.rules",
            }
            self.assertTrue(set(expected).issubset(files))
            for destination, source in expected.items():
                self.assertEqual(files[destination], source.read_bytes())
            compile(files["/usr/local/lib/honeyforge/high-telemetry-sensor"], "sensor", "exec")
            compile(files["/usr/local/lib/honeyforge/high_telemetry_audit.py"], "audit", "exec")
            unit = files["/etc/systemd/system/honeyforge-high-telemetry.service"].decode()
            self.assertIn("ExecStart=/usr/local/lib/honeyforge/high-telemetry-sensor", unit)
            self.assertIn("ProtectSystem=strict", unit)
            self.assertIn("UMask=0077", unit)

    def test_high_kazik_pump_uses_durable_center_ack(self):
        agent_main = (RECIPE.parents[1] / "crates/hf-agent/src/main.rs").read_text(encoding="utf-8")
        high_agent = (RECIPE.parents[1] / "crates/hf-agent/src/high_telemetry.rs").read_text(encoding="utf-8")
        center_main = (RECIPE.parents[1] / "crates/hf-center/src/main.rs").read_text(encoding="utf-8")
        center_store = (RECIPE.parents[1] / "crates/hf-center/src/telemetry_store.rs").read_text(encoding="utf-8")
        self.assertIn("enqueue_next_high_telemetry_batch", agent_main)
        self.assertIn("acknowledge_center_batch", agent_main)
        self.assertIn("prepare_kazik_batch", agent_main)
        self.assertIn("acknowledge_durable_kazik_batch", high_agent)
        self.assertIn(".persist(envelope.agent_id, events)", center_main)
        self.assertIn("self.file.sync_data()", center_store)


class MultiOsRecipeTests(unittest.TestCase):
    def test_arch_cloud_init_embeds_both_valid_python_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            executable(fake_bin / "qemu-img", "#!/bin/sh\n: > \"$8\"\n")
            executable(fake_bin / "cloud-localds", "#!/bin/sh\nshift\n: > \"$1\"\n")
            executable(fake_bin / "virt-customize", "#!/bin/sh\nexit 0\n")
            base_image = root / "arch.qcow2"
            base_image.write_bytes(b"test base")
            instance = root / "instance"
            environment = dict(os.environ)
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

            subprocess.run(
                [
                    "sh",
                    str(ARCH_RECIPE / "scripts/create-overlay.sh"),
                    str(base_image),
                    str(instance),
                    "11111111-2222-4333-8444-555555555555",
                ],
                check=True,
                env=environment,
                capture_output=True,
                text=True,
            )

            user_data = (instance / "user-data").read_text(encoding="utf-8")
            self.assertNotIn("@@", user_data)
            files = embedded_files(user_data)
            sensor = files["/usr/local/lib/honeyforge/high-telemetry-sensor"]
            audit = files["/usr/local/lib/honeyforge/high_telemetry_audit.py"]
            self.assertEqual(sensor, (RECIPE / "guest/high_telemetry_sensor.py").read_bytes())
            self.assertEqual(audit, (RECIPE / "guest/high_telemetry_audit.py").read_bytes())
            compile(sensor, "arch-sensor", "exec")
            compile(audit, "arch-audit", "exec")

    def test_windows_answer_file_is_unattended_and_sets_the_admin_password(self):
        answer = WINDOWS_RECIPE / "autounattend.xml"
        document = ET.parse(answer)
        namespace = {"u": "urn:schemas-microsoft-com:unattend"}
        self.assertIsNotNone(document.find(".//u:DiskConfiguration", namespace))
        self.assertIsNotNone(document.find(".//u:ImageInstall", namespace))
        self.assertIsNotNone(document.find(".//u:AdministratorPassword", namespace))
        contents = answer.read_text(encoding="utf-8")
        self.assertEqual(contents.count("@@ADMIN_PASSWORD@@"), 1)
        self.assertIn("Microsoft-Windows-TerminalServices-LocalSessionManager", contents)
        self.assertNotIn("<AutoLogon>", contents)

    def test_windows_answer_file_generation_removes_markers_and_protects_password(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            executable(fake_bin / "qemu-img", "#!/bin/sh\n: > \"$4\"\n")
            executable(
                fake_bin / "xorriso",
                "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = -o ]; then shift; : > \"$1\"; exit 0; fi\n"
                "  shift\n"
                "done\nexit 1\n",
            )
            base_iso = root / "windows.iso"
            base_iso.write_bytes(b"test media")
            instance = root / "instance"
            environment = dict(os.environ)
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

            subprocess.run(
                [
                    "sh",
                    str(WINDOWS_RECIPE / "scripts/create-overlay.sh"),
                    str(base_iso),
                    str(instance),
                    "11111111-2222-4333-8444-555555555555",
                ],
                check=True,
                env=environment,
                capture_output=True,
                text=True,
            )

            password_file = instance / "rdp-password"
            password = password_file.read_text(encoding="utf-8").strip()
            answer = (instance / "Autounattend.xml").read_text(encoding="utf-8")
            self.assertGreaterEqual(len(password), 24)
            self.assertNotIn("@@", answer)
            self.assertEqual(answer.count(password), 1)
            self.assertEqual(stat.S_IMODE(password_file.stat().st_mode), 0o600)
            self.assertTrue((instance / "seed.iso").is_file())

    def test_registered_multi_os_recipe_scripts_are_present_and_valid(self):
        required = {
            "launch.sh",
            "create-overlay.sh",
            "create-network.sh",
            "firewall-common.sh",
            "publish-service.sh",
            "unpublish-service.sh",
            "check-publication.sh",
            "stop.sh",
            "reset.sh",
            "download-base-image.sh",
        }
        for recipe in (ARCH_RECIPE, WINDOWS_RECIPE):
            scripts = recipe / "scripts"
            self.assertTrue(required.issubset({path.name for path in scripts.glob("*.sh")}))
            for script in scripts.glob("*.sh"):
                subprocess.run(["sh", "-n", str(script)], check=True)

    def test_new_downloaders_require_https_and_sha256(self):
        for recipe in (ARCH_RECIPE, WINDOWS_RECIPE):
            script = (recipe / "scripts/download-base-image.sh").read_text(encoding="utf-8")
            self.assertIn("https://", script)
            self.assertIn("sha256sum", script)
            self.assertIn("checksum mismatch", script)

    def test_profile_wrappers_publish_the_expected_guest_ports(self):
        arch = (ARCH_RECIPE / "scripts/publish-service.sh").read_text(encoding="utf-8")
        windows = (WINDOWS_RECIPE / "scripts/publish-service.sh").read_text(encoding="utf-8")
        self.assertIn('"$2" 22', arch)
        self.assertIn('"$2" 3389', windows)
        self.assertIn("listen=127.0.0.1", (WINDOWS_RECIPE / "scripts/launch.sh").read_text())

    def test_recipe_bundle_contains_all_registered_os_adapters(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "high-recipes.tar.gz"
            subprocess.run(
                ["sh", str(SCRIPTS / "package-recipe.sh"), str(archive)],
                check=True,
                capture_output=True,
                text=True,
            )
            with tarfile.open(archive) as bundle:
                names = {member.name.split("/", 1)[0] for member in bundle.getmembers()}
            self.assertEqual(
                names,
                {
                    "high-ubuntu-ssh",
                    "high-debian-ssh",
                    "high-arch-ssh",
                    "high-windows-rdp",
                    "high-custom-iso",
                    "hf-image-builder",
                },
            )


class FirewallPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "iptables.json"
        fake_iptables = r'''#!/usr/bin/env python3
import json, os, sys
path = os.environ["FAKE_IPTABLES_STATE"]
family = os.path.basename(sys.argv[0])
args = sys.argv[1:]
if args[:2] == ["-w", "5"]: args = args[2:]
table = "filter"
if args[:1] == ["-t"]:
    table, args = args[1], args[2:]
operation, chain, rest = args[0], args[1], args[2:]
try: state = json.load(open(path))
except FileNotFoundError: state = {}
key = family + ":" + table
chains = state.setdefault(key, {name: [] for name in ["INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"]})
status = 0
if operation == "-N":
    if chain in chains: status = 1
    else: chains[chain] = []
elif operation == "-L": status = 0 if chain in chains else 1
elif operation == "-F":
    if chain not in chains: status = 1
    else: chains[chain] = []
elif operation == "-C": status = 0 if rest in chains.get(chain, []) else 1
elif operation == "-A": chains.setdefault(chain, []).append(rest)
elif operation == "-I":
    position = int(rest.pop(0)) if rest and rest[0].isdigit() else 1
    chains.setdefault(chain, []).insert(position - 1, rest)
elif operation == "-D":
    try: chains[chain].remove(rest)
    except (KeyError, ValueError): status = 1
else: status = 2
with open(path, "w") as handle: json.dump(state, handle, sort_keys=True)
sys.exit(status)
'''
        executable(self.bin / "iptables", fake_iptables)
        os.symlink(self.bin / "iptables", self.bin / "ip6tables")
        executable(
            self.bin / "iptables-save",
            r'''#!/usr/bin/env python3
import json, os
try: state = json.load(open(os.environ["FAKE_IPTABLES_STATE"]))
except FileNotFoundError: state = {}
for chain, rules in state.get("iptables:nat", {}).items():
    for rule in rules: print("-A", chain, *rule)
''',
        )
        executable(
            self.bin / "virsh",
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  domifaddr) printf ' vnet0 52:54:00:00:00:01 ipv4 %s/24\\n' \"${FAKE_GUEST_IP:-192.168.250.100}\";;\n"
            "  dominfo) if [ -n \"${FAKE_DOMAIN_EXISTS:-}\" ]; then exit 0; else exit 1; fi;;\n"
            "  net-info) printf 'Active:         yes\\n';;\n"
            "  net-dumpxml) if [ -n \"${FAKE_BAD_NETWORK:-}\" ]; then printf \"<network><name>hf-high-isolated</name><forward mode='nat'/><bridge name='virbr0'/></network>\\n\"; else printf \"<network><name>hf-high-isolated</name><forward mode='none'/><bridge name='virbr-hfhigh'/><ip address='192.168.250.1' netmask='255.255.255.0'><dhcp><range start='192.168.250.100' end='192.168.250.200'/></dhcp></ip></network>\\n\"; fi;;\n"
            "esac\n"
            "exit 0\n",
        )
        executable(self.bin / "ss", "#!/bin/sh\nexit 0\n")
        executable(
            self.bin / "ip",
            "#!/bin/sh\n"
            "if [ \"$1 $2 $3 $4\" = '-4 route show default' ]; then\n"
            "  printf 'default via 203.0.113.1 dev %s proto dhcp\\n' \"${FAKE_DEFAULT_INTERFACE:-eth0}\"\n"
            "elif [ \"$1 $2 $3\" = '-o link show' ] && [ \"$4\" = dev ]; then\n"
            "  [ \"$5\" != missing0 ]\n"
            "else\n"
            "  exit 1\n"
            "fi\n",
        )
        executable(self.bin / "sysctl", "#!/bin/sh\nexit 0\n")
        executable(self.bin / "virt-install", "#!/bin/sh\nexit 1\n")
        self.environment = dict(os.environ)
        self.environment.update(
            PATH=f"{self.bin}:{self.environment['PATH']}",
            FAKE_IPTABLES_STATE=str(self.state),
            HF_HIGH_ROOT=str(self.root / "high"),
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_iso_e2e_scope_uses_separate_network_bridge_subnet_and_chains(self):
        environment = dict(self.environment, HF_HIGH_NETWORK_SCOPE="e2e")
        result = subprocess.run(
            [
                "sh",
                "-c",
                '. "$1"; printf "%s\\n" "$HF_HIGH_NETWORK_NAME|$HF_HIGH_BRIDGE|$HF_HIGH_DHCP_START|$HF_HIGH_INPUT_CHAIN|$HF_HIGH_FORWARD_CHAIN|$HF_HIGH_DNAT_CHAIN"',
                "sh",
                str(SCRIPTS / "firewall-common.sh"),
            ],
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.stdout.strip(),
            "hf-high-iso-e2e|virbr-hfiso|192.168.251.100|HF_E2E_INPUT|HF_E2E_FORWARD|HF_E2E_DNAT",
        )

    def run_script(self, name, *arguments, check=True):
        return subprocess.run(
            ["sh", str(SCRIPTS / name), *map(str, arguments)],
            env=self.environment,
            check=check,
            capture_output=True,
            text=True,
        )

    def test_firewall_policy_is_early_complete_and_idempotent(self):
        self.run_script("create-network.sh")
        first = json.loads(self.state.read_text())
        self.run_script("create-network.sh")
        self.assertEqual(first, json.loads(self.state.read_text()))

        trap_id = "11111111-2222-4333-8444-555555555555"
        instance = self.root / "high" / trap_id
        instance.mkdir(parents=True)
        (instance / "external-ssh-port").write_text("22022\n", encoding="ascii")
        self.run_script("publish-ssh.sh", trap_id, "22022")
        published = json.loads(self.state.read_text())
        self.run_script("publish-ssh.sh", trap_id, "22022")
        self.assertEqual(published, json.loads(self.state.read_text()))

        ipv4_filter = published["iptables:filter"]
        self.assertEqual(ipv4_filter["INPUT"][0], ["-i", "virbr-hfhigh", "-j", "HF_HIGH_INPUT"])
        self.assertEqual(
            ipv4_filter["HF_HIGH_INPUT"],
            [
                ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                ["-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"],
                ["-j", "DROP"],
            ],
        )
        self.assertEqual(ipv4_filter["HF_HIGH_FORWARD"][-1], ["-j", "DROP"])
        self.assertIn(["-i", "virbr-hfhigh", "-j", "HF_HIGH_FORWARD"], ipv4_filter["FORWARD"][:2])
        self.assertIn(["-o", "virbr-hfhigh", "-j", "HF_HIGH_FORWARD"], ipv4_filter["FORWARD"][:2])
        dnat = published["iptables:nat"]["HF_HIGH_DNAT"][0]
        self.assertEqual(
            dnat[:6], ["-i", "eth0", "-m", "addrtype", "--dst-type", "LOCAL"]
        )
        self.assertNotIn("!", dnat)
        self.assertNotIn("docker0", json.dumps(published["iptables:nat"]))
        self.assertIn(
            [
                "-i", "eth0", "-o", "virbr-hfhigh", "-p", "tcp",
                "-d", "192.168.250.100", "--dport", "22", "-m", "conntrack",
                "--ctstate", "NEW,ESTABLISHED", "-j", "ACCEPT",
            ],
            ipv4_filter["HF_HIGH_FORWARD"],
        )
        self.assertIn(
            [
                "-i", "virbr-hfhigh", "-o", "eth0", "-p", "tcp",
                "-s", "192.168.250.100", "--sport", "22", "-m", "conntrack",
                "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT",
            ],
            ipv4_filter["HF_HIGH_FORWARD"],
        )
        self.assertEqual(
            published["ip6tables:filter"]["HF_HIGH_INPUT6"],
            [
                ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                ["-j", "DROP"],
            ],
        )
        self.assertEqual((instance / "publish-interface").read_text().strip(), "eth0")
        self.run_script("check-dnat.sh", trap_id)

        self.environment["FAKE_GUEST_IP"] = "192.168.250.101"
        self.run_script("publish-ssh.sh", trap_id, "22022")
        moved = json.loads(self.state.read_text())
        self.assertNotIn("192.168.250.100:22", json.dumps(moved["iptables:nat"]))
        self.assertIn("192.168.250.101:22", json.dumps(moved["iptables:nat"]))
        self.assertEqual((instance / "guest-ip").read_text().strip(), "192.168.250.101")

        self.run_script("unpublish-ssh.sh", trap_id)
        unpublished = json.loads(self.state.read_text())
        self.assertEqual(unpublished["iptables:nat"]["HF_HIGH_DNAT"], [])
        self.assertEqual(unpublished["iptables:filter"]["HF_HIGH_FORWARD"], [["-j", "DROP"]])

    def test_publication_moves_atomically_to_an_explicit_interface(self):
        self.run_script("create-network.sh")
        trap_id = "11111111-2222-4333-8444-555555555555"
        instance = self.root / "high" / trap_id
        instance.mkdir(parents=True)
        (instance / "external-ssh-port").write_text("22022\n", encoding="ascii")

        self.run_script("publish-ssh.sh", trap_id, "22022")
        self.environment["HF_HIGH_PUBLISH_INTERFACE"] = "ens19"
        self.run_script("publish-ssh.sh", trap_id, "22022")
        moved = json.loads(self.state.read_text())

        rules = json.dumps(moved)
        self.assertNotIn('"eth0"', rules)
        self.assertIn('"ens19"', rules)
        self.assertEqual((instance / "publish-interface").read_text().strip(), "ens19")
        self.run_script("check-dnat.sh", trap_id)

    def test_health_check_rejects_duplicate_dnat_on_an_unwanted_interface(self):
        self.run_script("create-network.sh")
        trap_id = "11111111-2222-4333-8444-555555555555"
        instance = self.root / "high" / trap_id
        instance.mkdir(parents=True)
        (instance / "external-ssh-port").write_text("22022\n", encoding="ascii")
        self.run_script("publish-ssh.sh", trap_id, "22022")

        state = json.loads(self.state.read_text())
        state["iptables:nat"]["HF_HIGH_DNAT"].append(
            [
                "-i", "docker0", "-m", "addrtype", "--dst-type", "LOCAL",
                "-p", "tcp", "--dport", "22022", "-j", "DNAT",
                "--to-destination", "192.168.250.100:22",
            ]
        )
        self.state.write_text(json.dumps(state), encoding="utf-8")

        result = self.run_script("check-dnat.sh", trap_id, check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_publication_rejects_ambiguous_or_unsafe_interfaces(self):
        executable(
            self.bin / "ip",
            "#!/bin/sh\n"
            "if [ \"$1 $2 $3 $4\" = '-4 route show default' ]; then\n"
            "  printf 'default via 203.0.113.1 dev eth0\\n'\n"
            "  printf 'default via 198.51.100.1 dev ens19\\n'\n"
            "elif [ \"$1 $2 $3\" = '-o link show' ] && [ \"$4\" = dev ]; then exit 0\n"
            "else exit 1; fi\n",
        )
        result = self.run_script(
            "publish-ssh.sh", "11111111-2222-4333-8444-555555555555", "22022", check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("set HF_HIGH_PUBLISH_INTERFACE", result.stderr)

        self.environment["HF_HIGH_PUBLISH_INTERFACE"] = "lo"
        result = self.run_script(
            "publish-ssh.sh", "11111111-2222-4333-8444-555555555555", "22022", check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("isolated or loopback", result.stderr)

    def test_management_ssh_port_is_never_published(self):
        result = self.run_script(
            "publish-ssh.sh", "11111111-2222-4333-8444-555555555555", "2222", check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reserved for host management", result.stderr)

    def test_publication_supports_a_profile_specific_guest_service_port(self):
        self.run_script("create-network.sh")
        trap_id = "11111111-2222-4333-8444-555555555555"
        instance = self.root / "high" / trap_id
        instance.mkdir(parents=True)
        (instance / "external-ssh-port").write_text("23389\n", encoding="ascii")

        self.run_script("publish-ssh.sh", trap_id, "23389", "3389")
        self.run_script("check-dnat.sh", trap_id)
        published = json.loads(self.state.read_text())
        self.assertIn("192.168.250.100:3389", json.dumps(published["iptables:nat"]))
        self.assertIn(
            [
                "-i", "eth0", "-o", "virbr-hfhigh", "-p", "tcp",
                "-d", "192.168.250.100", "--dport", "3389", "-m", "conntrack",
                "--ctstate", "NEW,ESTABLISHED", "-j", "ACCEPT",
            ],
            published["iptables:filter"]["HF_HIGH_FORWARD"],
        )
        self.assertIn(
            [
                "-i", "virbr-hfhigh", "-o", "eth0", "-p", "tcp",
                "-s", "192.168.250.100", "--sport", "3389", "-m", "conntrack",
                "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT",
            ],
            published["iptables:filter"]["HF_HIGH_FORWARD"],
        )
        self.assertEqual((instance / "guest-service-port").read_text().strip(), "3389")

        self.run_script("unpublish-ssh.sh", trap_id)
        unpublished = json.loads(self.state.read_text())
        self.assertNotIn("192.168.250.100:3389", json.dumps(unpublished))

    def test_mismatched_existing_libvirt_network_is_rejected(self):
        self.environment["FAKE_BAD_NETWORK"] = "1"
        result = self.run_script("create-network.sh", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the fail-closed profile", result.stderr)

    def test_existing_docker_or_high_dnat_port_is_not_stolen(self):
        self.run_script("create-network.sh")
        state = json.loads(self.state.read_text())
        state["iptables:nat"]["DOCKER"] = [
            ["-p", "tcp", "--dport", "22022", "-j", "DNAT", "--to-destination", "172.17.0.2:22"]
        ]
        self.state.write_text(json.dumps(state), encoding="utf-8")
        result = self.run_script(
            "publish-ssh.sh", "11111111-2222-4333-8444-555555555555", "22022", check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("host NAT/redirect rule", result.stderr)

    def test_guest_address_outside_isolated_dhcp_range_is_rejected(self):
        self.environment["FAKE_GUEST_IP"] = "192.168.1.25"
        result = self.run_script(
            "publish-ssh.sh", "11111111-2222-4333-8444-555555555555", "22022", check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the High DHCP range", result.stderr)

    def test_destructive_lifecycle_scripts_reject_non_uuid_paths(self):
        result = self.run_script("reset.sh", "../../not-an-instance", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid High instance UUID", result.stderr)

    def test_launch_never_cleans_an_existing_domain_and_cleans_failed_new_artifacts(self):
        trap_id = "11111111-2222-4333-8444-555555555555"
        instance = self.root / "high" / trap_id
        instance.mkdir(parents=True)
        marker = instance / "preserve"
        marker.write_text("existing", encoding="ascii")
        base = self.root / "base.qcow2"
        base.write_bytes(b"base")

        self.environment["FAKE_DOMAIN_EXISTS"] = "1"
        result = self.run_script("launch.sh", base, trap_id, "22022", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(marker.exists())

        del self.environment["FAKE_DOMAIN_EXISTS"]
        executable(self.bin / "qemu-img", "#!/bin/sh\nexit 1\n")
        result = self.run_script("launch.sh", base, trap_id, "22022", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(instance.exists())

    def test_shell_scripts_are_syntactically_valid(self):
        for script in SCRIPTS.glob("*.sh"):
            subprocess.run(["sh", "-n", str(script)], check=True)


if __name__ == "__main__":
    unittest.main()
