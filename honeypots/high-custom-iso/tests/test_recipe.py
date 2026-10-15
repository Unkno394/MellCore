import base64
import hashlib
import importlib.util
import io
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


RECIPE = pathlib.Path(__file__).resolve().parents[1]
INSTANCE_ID = "11111111-2222-4333-8444-555555555555"


def load_arch_repository_module():
    path = RECIPE / "scripts" / "prepare-arch-repository.py"
    spec = importlib.util.spec_from_file_location("hf_prepare_arch_repository", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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
        self.assertIn("mklabel msdos", guest)
        self.assertIn("ARCH_PARTITION_VERIFY_FAILED", guest)
        self.assertIn("/usr/lib/modules/*/vmlinuz", guest)
        self.assertIn("install -Dm0644 \"$kernel_source\" /mnt/boot/vmlinuz-linux", guest)
        self.assertIn("PRESETS=('default')", guest)
        self.assertNotIn("PRESETS=('archiso')", guest)
        self.assertIn("ARCH_INITRAMFS_BUILD_FAILED", guest)
        self.assertIn("ARCH_INITRAMFS_VERIFY_FAILED", guest)
        self.assertIn("ARCH_GRUB_INSTALL_FAILED", guest)
        self.assertIn("ARCH_GRUB_CONFIG_FAILED", guest)
        self.assertIn("grep -F \"$root_uuid\"", guest)
        self.assertIn("/boot/grub/i386-pc/core.img", guest)
        self.assertIn("ARCH_POWER_OFF_REQUEST_FAILED", guest)
        self.assertLess(
            guest.index("ARCH_INITRAMFS_BUILD_FAILED"),
            guest.index("printf '%s\\n' installed > /mnt/etc/honeyforge-installed"),
        )
        self.assertLess(
            guest.index("ARCH_GRUB_VERIFY_FAILED"),
            guest.index("printf '%s\\n' installed > /mnt/etc/honeyforge-installed"),
        )
        self.assertIn("code=ARCH_POWER_OFF_TIMEOUT", arch)
        self.assertIn("code=ARCH_INSTALL_MARKER_MISSING", arch)
        self.assertIn("code=ARCH_BOOT_ARTIFACT_MISSING", arch)

        console = (RECIPE / "scripts" / "arch-console.exp").read_text()
        self.assertIn("HF_INSTALL_FAILED:([A-Z0-9_]+)", console)
        self.assertIn("HF_INSTALL_RESULT:([0-9]+)", console)
        self.assertIn("guest installer exited with status $status", console)
        self.assertIn("/run/hf-install-result.tmp", console)
        self.assertNotIn("test -e /mnt/etc/honeyforge-installed && echo HF_INSTALL_COMPLETE", console)
        self.assertIn("completed_before_prompt", console)
        self.assertLess(
            console.index("HF_INSTALL_RESULT:([0-9]+)"),
            console.index("-re {(?i)archiso[[:space:]]+login:}"),
        )

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

    def test_archinstall_uses_read_only_offline_repository_and_keeps_legacy_fallback(self):
        launch = (RECIPE / "scripts" / "launch-iso.sh").read_text()
        install = (RECIPE / "scripts" / "install-arch.sh").read_text()
        guest = (RECIPE / "scripts" / "archinstall-guest-install.sh").read_text()
        self.assertIn("prepare-arch-repository.py", launch)
        self.assertIn("device=cdrom,readonly=on", launch)
        self.assertIn("HF_HIGH_ARCH_INSTALL_METHOD:-archinstall", launch)
        self.assertIn("arch_install_method=legacy", launch)
        self.assertNotIn("python3 -m http.server", launch)
        self.assertIn('archinstall) guest_installer="$script_dir/archinstall-guest-install.sh"', install)
        self.assertIn('legacy) guest_installer="$script_dir/arch-guest-install.sh"', install)
        self.assertIn("HF_ARCH_REPO", guest)
        self.assertIn("Server = file://$repo_mount/\\$repo/os/\\$arch", guest)
        self.assertIn("3.0.8|3.0.9", guest)
        for option in ("--offline", "--skip-version-check", "--skip-ntp", "--skip-wkd", "--dry-run"):
            self.assertIn(option, guest)
        self.assertIn("ARCHINSTALL_CONFIG_INVALID", guest)
        self.assertIn("SigLevel = Required DatabaseOptional", guest)
        self.assertIn("LocalFileSigLevel = Required", guest)
        self.assertIn("ARCH_REPO_METADATA_INVALID", guest)
        self.assertIn("ARCH_REPO_PACKAGE_SIGNATURE_MISSING", guest)
        self.assertIn("ARCH_REPO_PACKAGE_SIGNATURE_INVALID", guest)
        self.assertIn("ARCH_REPO_PACKAGE_SIGNING_KEY_EXPIRED", guest)
        self.assertIn("ARCH_REPO_PACKAGE_SIGNATURE_TIMEOUT", guest)
        self.assertIn("ARCH_REPO_KEYRING_INSTALL_FAILED", guest)
        self.assertIn("archlinux-keyring 20260909-1", guest)
        self.assertIn('timeout 30 pacman-key --verify "$package_path.sig" "$package_path"', guest)
        self.assertIn("pacman-key --init", guest)
        self.assertIn("pacman-key --populate archlinux", guest)
        self.assertIn("ARCH_PACMAN_KEYRING_NOT_READY", guest)
        self.assertIn("\\[expired\\]", guest)
        self.assertIn("systemd-time-wait-sync.service", guest)
        self.assertIn("reflector.service", guest)
        self.assertNotIn("SigLevel = Never", guest)
        self.assertNotIn("TrustAll", guest)
        self.assertNotIn("date -s", guest)
        self.assertLess(guest.index("pacman-key --populate archlinux"), guest.index("pacman -Sy --noconfirm"))
        self.assertLess(
            guest.index("installing approved Arch keyring"),
            guest.index("pacman -Sy --noconfirm"),
        )
        self.assertLess(
            guest.index("if grep -Eiq 'key has expired"),
            guest.index('if [ "$signature_status" -ne 0 ]'),
        )
        self.assertNotIn("core.db.sig", guest)
        self.assertNotIn("extra.db.sig", guest)
        self.assertIn('"sudo": true', guest)
        self.assertIn("ARCH_USER_PRIVILEGE_REMOVE_FAILED", guest)
        self.assertIn("usermod -G systemd-journal analyst", guest)
        self.assertLess(
            guest.index("ARCH_BOOT_ARTIFACT_MISSING"),
            guest.index("printf '%s\\n' installed > /mnt/etc/honeyforge-installed"),
        )

    def test_arch_repository_catalog_is_fixed_and_resolves_transitive_providers(self):
        repository = load_arch_repository_module()
        self.assertEqual(repository.SOURCE_ROOT, "https://archive.archlinux.org/repos/2026/09/10")
        self.assertEqual(repository.ARCH, "x86_64")
        self.assertEqual(repository.KEYRING_VERSION, "20260909-1")
        self.assertEqual(
            repository.KEYRING_PACKAGE_SHA256,
            "6a8ea16f51d3b305c18322d5884ca959f12c32a3f186873090fdc18465605293",
        )
        self.assertEqual(
            repository.KEYRING_SIGNATURE_SHA256,
            "5942acd5b5e27a45051c447b8054696465872e834af1a5bd3cb85e2881cf6cf8",
        )
        digest = "a" * 64
        packages = [
            repository.Package("core", "root", "root.pkg.tar.zst", digest, 1, ("virtual>=1",), ()),
            repository.Package("core", "provider-a", "provider-a.pkg.tar.zst", digest, 1, ("leaf",), ("virtual=1",)),
            repository.Package("extra", "provider-b", "provider-b.pkg.tar.zst", digest, 1, (), ("virtual=1",)),
            repository.Package("core", "leaf", "leaf.pkg.tar.zst", digest, 1, (), ()),
        ]
        resolved = repository.resolve_packages(packages, ("root",))
        self.assertEqual(
            {package.name for package in resolved},
            {"root", "provider-a", "provider-b", "leaf"},
        )

    def test_arch_repository_database_parser_rejects_missing_checksums(self):
        repository = load_arch_repository_module()
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "core.db"
            description = b"%NAME%\nbase\n\n%FILENAME%\nbase.pkg.tar.zst\n\n%CSIZE%\n10\n"
            with tarfile.open(database, "w:gz") as archive:
                info = tarfile.TarInfo("base-1/desc")
                info.size = len(description)
                archive.addfile(info, io.BytesIO(description))
            with self.assertRaises(repository.RepositoryError) as caught:
                repository.parse_database("core", database)
            self.assertEqual(caught.exception.code, "ARCH_REPO_DATABASE_INVALID")

    def test_arch_repository_manifest_pins_database_content_without_requiring_db_signatures(self):
        repository = load_arch_repository_module()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            core = root / "core.db"
            extra = root / "extra.db"
            core.write_bytes(b"core metadata")
            extra.write_bytes(b"extra metadata")
            manifest = repository.repository_manifest({"core": core, "extra": extra}, [])
            self.assertEqual(manifest["format_version"], 3)
            self.assertFalse(manifest["database_signatures_required"])
            self.assertEqual(manifest["bootstrap_keyring"]["version"], "20260909-1")
            self.assertEqual(manifest["databases"]["core"], hashlib.sha256(b"core metadata").hexdigest())
            self.assertEqual(manifest["databases"]["extra"], hashlib.sha256(b"extra metadata").hexdigest())

    def test_arch_repository_listing_accepts_xorriso_shell_quoted_paths(self):
        repository = load_arch_repository_module()
        listing = repository.parse_xorriso_listing(
            "'/core/os/x86_64/core.db'\n"
            "'/extra/os/x86_64/extra.db'\n"
            "'/HF-ARCH-REPO.json'\n"
        )
        self.assertEqual(
            listing,
            {
                "/core/os/x86_64/core.db",
                "/extra/os/x86_64/extra.db",
                "/HF-ARCH-REPO.json",
            },
        )
        self.assertEqual(repository.parse_xorriso_listing("diagnostic text\n'unclosed\n"), set())

    @unittest.skipUnless(shutil.which("xorriso"), "xorriso is required for a real ISO test")
    def test_arch_repository_validator_accepts_a_real_small_xorriso_image(self):
        repository = load_arch_repository_module()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            staging = root / "staging"
            for name in ("core", "extra"):
                target = staging / name / "os" / "x86_64"
                target.mkdir(parents=True)
                (target / f"{name}.db").write_bytes(f"{name} database fixture".encode())
            keyring = staging / "core" / "os" / "x86_64" / repository.KEYRING_FILENAME
            keyring.write_bytes(b"keyring fixture")
            keyring.with_name(keyring.name + ".sig").write_bytes(b"signature fixture")
            (staging / "HF-ARCH-REPO.json").write_text("{}\n", encoding="utf-8")
            image = root / "repository.iso"
            completed = subprocess.run(
                [
                    shutil.which("xorriso"),
                    "-as",
                    "mkisofs",
                    "-quiet",
                    "-r",
                    "-V",
                    "HF_ARCH_REPO",
                    "-o",
                    str(image),
                    str(staging),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            checksum = image.with_suffix(".iso.sha256")
            self.assertTrue(repository.validate_cached_iso(image, checksum))
            self.assertTrue(checksum.is_file())

    def test_arch_repository_validator_reports_exit_missing_paths_and_listing(self):
        repository = load_arch_repository_module()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            image = root / "repository.iso"
            image.write_bytes(b"ISO fixture")
            result = subprocess.CompletedProcess(
                args=["xorriso"],
                returncode=5,
                stdout="'/core/os/x86_64/core.db'\n",
                stderr="xorriso : FAILURE : fixture read error\n",
            )
            with mock.patch.object(repository.subprocess, "run", return_value=result) as run_mock:
                with self.assertRaises(repository.RepositoryError) as caught:
                    repository.validate_cached_iso(image, root / "repository.iso.sha256")
            command = run_mock.call_args.args[0]
            self.assertIn("-sh_style_result", command)
            self.assertEqual(command[-6:], ["-find", "/", "-type", "f", "-exec", "echo"])
            detail = str(caught.exception)
            self.assertIn("xorriso_exit=5", detail)
            self.assertIn("/extra/os/x86_64/extra.db", detail)
            self.assertIn("/HF-ARCH-REPO.json", detail)
            self.assertIn("discovered=/core/os/x86_64/core.db", detail)
            self.assertIn("fixture read error", detail)

    def test_arch_package_signature_download_has_specific_diagnostic(self):
        repository = load_arch_repository_module()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            executable(fake_bin / "curl", "#!/bin/sh\nexit 22\n")
            with mock.patch.dict(os.environ, {"PATH": f"{fake_bin}:{os.environ['PATH']}"}):
                with self.assertRaises(repository.RepositoryError) as caught:
                    repository.download(
                        "https://archive.archlinux.org/missing.pkg.tar.zst.sig",
                        root / "missing.pkg.tar.zst.sig",
                        1024,
                        None,
                        "ARCH_REPO_PACKAGE_SIGNATURE_MISSING",
                    )
            self.assertEqual(caught.exception.code, "ARCH_REPO_PACKAGE_SIGNATURE_MISSING")

    def test_arch_signature_status_rejects_expired_revoked_and_untrusted_keys(self):
        repository = load_arch_repository_module()
        fingerprint = "A" * 40
        self.assertEqual(
            repository.parse_revoked_fingerprints(f"{fingerprint}\n{'B' * 40}:4:\ninvalid\n"),
            {fingerprint, "B" * 40},
        )
        valid = f"[GNUPG:] VALIDSIG {fingerprint} 2026 0 4 0 1 10 00 {fingerprint}\n"
        self.assertIsNone(
            repository.signature_status_error(valid + "[GNUPG:] TRUST_FULLY 0 pgp\n", set())
        )
        self.assertEqual(
            repository.signature_status_error(
                valid + "[GNUPG:] EXPKEYSIG DEADBEEF signer\n[GNUPG:] TRUST_FULLY 0 pgp\n",
                set(),
            ),
            "EXPKEYSIG",
        )
        self.assertEqual(
            repository.signature_status_error(valid + "[GNUPG:] TRUST_FULLY 0 pgp\n", {fingerprint}),
            "REVOKED_FINGERPRINT",
        )
        self.assertEqual(repository.signature_status_error(valid, set()), "SIGNER_NOT_TRUSTED")

    def test_arch_signature_preflight_checks_every_package(self):
        repository = load_arch_repository_module()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            keyring = root / repository.KEYRING_FILENAME
            keyring.write_bytes(b"keyring fixture")
            packages = []
            for name in ("one", "two"):
                filename = f"{name}-1-x86_64.pkg.tar.zst"
                (root / filename).write_bytes(name.encode())
                (root / f"{filename}.sig").write_bytes(b"signature")
                packages.append(repository.Package("core", name, filename, "a" * 64, 1, (), ()))

            def extract(_package, member, destination):
                if member.endswith("archlinux-revoked"):
                    destination.write_text("", encoding="ascii")
                elif member.endswith("archlinux-trusted"):
                    destination.write_text(f"{'B' * 40}:4:\n", encoding="ascii")
                else:
                    destination.write_bytes(b"public keys")

            fingerprint = "A" * 40

            def run(command, **_kwargs):
                if "--verify" in command:
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=(
                            f"[GNUPG:] VALIDSIG {fingerprint} 2026 0 4 0 1 10 00 {fingerprint}\n"
                            "[GNUPG:] TRUST_FULLY 0 pgp\n"
                        ),
                        stderr="",
                    )
                return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

            with mock.patch.object(
                repository, "KEYRING_PACKAGE_SHA256", hashlib.sha256(b"keyring fixture").hexdigest()
            ), mock.patch.object(repository, "extract_keyring_file", side_effect=extract), mock.patch.object(
                repository.subprocess, "run", side_effect=run
            ) as run_mock:
                repository.preflight_package_signatures(root, packages)
            verified = [call for call in run_mock.call_args_list if "--verify" in call.args[0]]
            self.assertEqual(len(verified), 2)

    def test_arch_repository_build_is_atomic_and_reuses_verified_iso(self):
        repository = load_arch_repository_module()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            downloads = root / "downloads"
            downloads.mkdir()
            fake_bin = root / "bin"
            fake_bin.mkdir()
            calls = root / "curl-calls"

            package_files = {
                "root-1-x86_64.pkg.tar.zst": b"root package",
                "leaf-1-x86_64.pkg.tar.zst": b"leaf package",
                repository.KEYRING_FILENAME: b"keyring package",
            }
            for filename, content in package_files.items():
                (downloads / filename).write_bytes(content)
                (downloads / f"{filename}.sig").write_bytes(b"detached signature")

            def write_database(name, descriptions):
                path = downloads / f"{name}.db"
                with tarfile.open(path, "w:gz") as archive:
                    for package_name, filename, dependencies in descriptions:
                        digest = hashlib.sha256((downloads / filename).read_bytes()).hexdigest()
                        description = (
                            f"%NAME%\n{package_name}\n\n%FILENAME%\n{filename}\n\n"
                            f"%SHA256SUM%\n{digest}\n\n%CSIZE%\n{(downloads / filename).stat().st_size}\n\n"
                        )
                        if dependencies:
                            description += "%DEPENDS%\n" + "\n".join(dependencies) + "\n\n"
                        payload = description.encode()
                        info = tarfile.TarInfo(f"{package_name}-1/desc")
                        info.size = len(payload)
                        archive.addfile(info, io.BytesIO(payload))

            write_database(
                "core",
                [
                    ("root", "root-1-x86_64.pkg.tar.zst", ("leaf", "archlinux-keyring")),
                    ("archlinux-keyring", repository.KEYRING_FILENAME, ()),
                ],
            )
            write_database("extra", [("leaf", "leaf-1-x86_64.pkg.tar.zst", ())])
            executable(
                fake_bin / "curl",
                "#!/bin/sh\n"
                "output=\n"
                "while [ \"$#\" -gt 1 ]; do\n"
                "  [ \"$1\" = --output ] && { shift; output=$1; }\n"
                "  shift\n"
                "done\n"
                "url=$1\n"
                "name=${url##*/}\n"
                "printf '%s\\n' \"$url\" >> \"$FAKE_CURL_CALLS\"\n"
                "cp \"$FAKE_DOWNLOADS/$name\" \"$output\"\n",
            )
            executable(
                fake_bin / "xorriso",
                "#!/bin/sh\n"
                "case \" $* \" in\n"
                "*' -indev '*)\n"
                "  printf '%s\\n' /core/os/x86_64/core.db /extra/os/x86_64/extra.db /HF-ARCH-REPO.json \"/core/os/x86_64/$FAKE_KEYRING\" \"/core/os/x86_64/$FAKE_KEYRING.sig\"\n"
                "  exit 0 ;;\n"
                "esac\n"
                "output=\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  [ \"$1\" = -o ] && { shift; output=$1; }\n"
                "  shift\n"
                "done\n"
                "printf 'verified repository iso' > \"$output\"\n",
            )
            environment = dict(
                os.environ,
                PATH=f"{fake_bin}:{os.environ['PATH']}",
                FAKE_DOWNLOADS=str(downloads),
                FAKE_CURL_CALLS=str(calls),
                FAKE_KEYRING=repository.KEYRING_FILENAME,
            )
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
                repository, "ROOT_PACKAGES", ("root",)
            ), mock.patch.object(
                repository,
                "KEYRING_PACKAGE_SHA256",
                hashlib.sha256(package_files[repository.KEYRING_FILENAME]).hexdigest(),
            ), mock.patch.object(
                repository,
                "KEYRING_SIGNATURE_SHA256",
                hashlib.sha256(b"detached signature").hexdigest(),
            ), mock.patch.object(repository, "preflight_package_signatures") as preflight:
                first = repository.build_repository(root / "cache")
                first_calls = len(calls.read_text().splitlines())
                second = repository.build_repository(root / "cache")
            self.assertEqual(first, second)
            self.assertTrue(first.is_file())
            self.assertTrue(first.with_suffix(first.suffix + ".sha256").is_file())
            self.assertEqual(len(calls.read_text().splitlines()), first_calls)
            self.assertEqual(preflight.call_count, 2)
            self.assertNotIn(".db.sig", calls.read_text())
            self.assertIn("offline-repo-v3.iso", first.name)

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
                "offline=\"$source/etc/systemd/system\"\n"
                "grep -Fx 'After=' \"$offline/pacman-init.service.d/honeyforge-offline.conf\" >/dev/null || exit 22\n"
                "grep -Fx 'After=etc-pacman.d-gnupg.mount' \"$offline/pacman-init.service.d/honeyforge-offline.conf\" >/dev/null || exit 23\n"
                "for unit in systemd-time-wait-sync.service systemd-timesyncd.service reflector.service reflector.timer archlinux-keyring-wkd-sync.service archlinux-keyring-wkd-sync.timer; do\n"
                "  [ -L \"$offline/$unit\" ] && [ \"$(readlink \"$offline/$unit\")\" = /dev/null ] || exit 24\n"
                "done\n"
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
            systemd_root = repack_capture / "etc/systemd/system"
            offline_override = systemd_root / "pacman-init.service.d/honeyforge-offline.conf"
            self.assertIn("After=etc-pacman.d-gnupg.mount", offline_override.read_text())
            for unit in (
                "systemd-time-wait-sync.service",
                "systemd-timesyncd.service",
                "reflector.service",
                "reflector.timer",
                "archlinux-keyring-wkd-sync.service",
                "archlinux-keyring-wkd-sync.timer",
            ):
                self.assertTrue((systemd_root / unit).is_symlink())
                self.assertEqual(os.readlink(systemd_root / unit), "/dev/null")
            self.assertEqual(
                (instance / "unattended-arch.version").read_text().strip(),
                "arch-offline-init-v4",
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
                "import select, sys\n"
                "def emit(value):\n"
                "    sys.stdout.write(value); sys.stdout.flush()\n"
                "ansi_prompt = '\\x1b[?2004h\\x1b[1;31m#\\x1b[0m '\n"
                "if select.select([sys.stdin], [], [], 0.25)[0]: raise SystemExit(9)\n"
                "emit('Connected to domain fixture-vm\\r\\n')\n"
                "if sys.stdin.readline().strip(): raise SystemExit(10)\n"
                "if sys.stdin.readline().strip(): raise SystemExit(15)\n"
                "emit(ansi_prompt)\n"
                "setup = sys.stdin.readline()\n"
                "if not setup.startswith('stty -echo'): raise SystemExit(11)\n"
                "if 'HF_SERIAL_READY' in setup or 'HF_%s_READY' not in setup: raise SystemExit(16)\n"
                "emit('HF_SERIAL_READY\\r\\n# ')\n"
                "if not sys.stdin.readline().startswith('rm -f '): raise SystemExit(12)\n"
                "emit(ansi_prompt)\n"
                "chunks = 0\n"
                "while True:\n"
                "    line = sys.stdin.readline()\n"
                "    if line.startswith(\"printf '%s' '\"):\n"
                "        chunks += 1; emit('# '); continue\n"
                "    if line.startswith('base64 -d '): break\n"
                "    raise SystemExit(13)\n"
                "if chunks < 2: raise SystemExit(14)\n"
                "emit('echo HF_INSTALL_COMPLETE\\r\\nHF_INSTALL_RESULT:0\\r\\n')\n",
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
                    HF_HIGH_ARCH_BOOT_TIMEOUT_SECONDS="8",
                ),
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            diagnostic = console_log.read_text(encoding="utf-8")
            self.assertIn("Connected to domain", diagnostic)
            self.assertIn("<ESC>[1;31m#<ESC>[0m", diagnostic)
            self.assertIn("<redacted-payload>", diagnostic)
            self.assertNotIn(payload_value, diagnostic)
            self.assertNotIn(payload_value[:768], diagnostic)
            self.assertEqual(stat.S_IMODE(console_log.stat().st_mode), 0o600)

    @unittest.skipUnless(shutil.which("expect"), "expect is required for Arch console tests")
    def test_arch_console_reconnect_accepts_running_installer_completion_without_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            executable(
                fake_bin / "virsh",
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "sys.stdout.write('Connected to domain fixture-vm\\r\\n'); sys.stdout.flush()\n"
                "sys.stdin.readline()\n"
                "sys.stdout.write('archinstall resumed\\r\\necho HF_INSTALL_COMPLETE\\r\\nHF_INSTALL_RESULT:0\\r\\n'); sys.stdout.flush()\n",
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
                    HF_HIGH_ARCH_BOOT_TIMEOUT_SECONDS="5",
                ),
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("HF_INSTALL_RESULT:0", console_log.read_text(encoding="utf-8"))

    @unittest.skipUnless(shutil.which("expect"), "expect is required for Arch console tests")
    def test_arch_console_rejects_reflected_success_and_reports_installer_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            executable(
                fake_bin / "virsh",
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "sys.stdout.write('Connected to domain fixture-vm\\r\\n'); sys.stdout.flush()\n"
                "sys.stdin.readline()\n"
                "sys.stdout.write('# \\r\\n'); sys.stdout.flush()\n"
                "setup = sys.stdin.readline()\n"
                "sys.stdout.write('HF_SERIAL_READY\\r\\n# \\r\\n'); sys.stdout.flush()\n"
                "sys.stdin.readline(); sys.stdout.write('# \\r\\n'); sys.stdout.flush()\n"
                "while True:\n"
                "    line = sys.stdin.readline()\n"
                "    if line.startswith(\"printf '%s' '\"):\n"
                "        sys.stdout.write('# \\r\\n'); sys.stdout.flush(); continue\n"
                "    if line.startswith('base64 -d '): break\n"
                "    raise SystemExit(13)\n"
                "sys.stdout.write('echo HF_INSTALL_COMPLETE\\r\\n')\n"
                "sys.stdout.write('HF_INSTALL_FAILED:ARCH_FIXTURE_FAILED:package verification failed\\r\\n')\n"
                "sys.stdout.write('HF_INSTALL_RESULT:23\\r\\n'); sys.stdout.flush()\n",
            )
            payload = root / "payload.b64"
            payload.write_text(base64.b64encode(b"fixture" * 200).decode("ascii"), encoding="ascii")
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
                    HF_HIGH_ARCH_BOOT_TIMEOUT_SECONDS="5",
                ),
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(completed.returncode, 5, completed.stderr)
            self.assertIn("code=ARCH_FIXTURE_FAILED", completed.stderr)
            self.assertIn("package verification failed", completed.stderr)
            self.assertIn("installer exit status 23", completed.stderr)

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
                "sys.stdout.write('Connected to domain fixture-vm\\r\\n'); sys.stdout.flush()\n"
                "if sys.stdin.readline().strip(): raise SystemExit(10)\n"
                "sys.stdout.write('Booting ArchISO: module #7\\r\\n# kernel diagnostic continues\\r\\n'); sys.stdout.flush()\n"
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
            self.assertIn("# kernel diagnostic continues", console_log.read_text(encoding="utf-8"))

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
