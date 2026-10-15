import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hf_image_builder", ROOT / "builder.py")
builder = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = builder
SPEC.loader.exec_module(builder)


def source(url="https://download.microsoft.com/windows.iso", digest="a" * 64):
    return builder.ArtifactSource(
        "test ISO", url, digest, ("download.microsoft.com",), "windows.iso"
    )


def catalog_document(root, windows_digest):
    return {
        "version": 1,
        "profile": "windows-server-2022-eval-x64",
        "approval": {
            "microsoft_evaluation_license_accepted": True,
            "approved_by": "test-admin",
            "approved_at": "2026-01-01T00:00:00+00:00",
        },
        "image": {
            "index": 4,
            "name": "Windows Server 2022 SERVERDATACENTER",
            "edition_id": "ServerDatacenterEval",
        },
        "sources": {
            "windows_iso": {
                "local_path": str(root / "approved.iso"),
                "sha256": windows_digest,
                "cache_name": "windows.iso",
            },
            "virtio_iso": {
                "url": "https://virtio.example/virtio.iso",
                "sha256": "b" * 64,
                "allowed_hosts": ["virtio.example"],
                "cache_name": "virtio.iso",
            },
            "cloudbase_msi": {
                "url": "https://cloudbase.example/setup.msi",
                "sha256": "c" * 64,
                "allowed_hosts": ["cloudbase.example"],
                "cache_name": "cloudbase.msi",
            },
        },
        "directories": {
            "cache": str(root / "cache"),
            "images": str(root / "images"),
            "work": str(root / "work"),
            "logs": str(root / "logs"),
        },
    }


def config(root, **overrides):
    values = dict(
        windows_iso=source(),
        virtio_iso=builder.ArtifactSource(
            "VirtIO", "https://virtio.example/virtio.iso", "b" * 64, ("virtio.example",), "virtio.iso"
        ),
        cloudbase_msi=builder.ArtifactSource(
            "Cloudbase", "https://cloudbase.example/setup.msi", "c" * 64, ("cloudbase.example",), "cloudbase.msi"
        ),
        image_index=4,
        image_name="Windows Server 2022 SERVERDATACENTER",
        edition_id="ServerDatacenterEval",
        cache_dir=root / "cache",
        image_dir=root / "images",
        work_dir=root / "work",
        log_dir=root / "log",
        cleanup_sources=False,
    )
    values.update(overrides)
    return builder.Config(**values)


class SourceTests(unittest.TestCase):
    def test_only_approved_https_source_and_real_hash_are_accepted(self):
        source().validate()
        for bad in (
            source("http://download.microsoft.com/windows.iso"),
            source("https://evil.example/windows.iso"),
            source(digest="nope"),
            source("https://user:pass@download.microsoft.com/windows.iso"),
        ):
            with self.assertRaises(builder.BuildError):
                bad.validate()

    def test_environment_requires_license_and_all_trust_anchors(self):
        with self.assertRaisesRegex(builder.BuildError, "license"):
            builder.Config.from_env({})

    def test_cache_is_reverified_and_mismatch_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            artifact = root / "windows.iso"
            artifact.write_bytes(b"trusted")
            trusted = source(digest=hashlib.sha256(b"trusted").hexdigest())
            self.assertEqual(builder.download_to_cache(trusted, root), artifact)
            artifact.write_bytes(b"tampered")
            with self.assertRaisesRegex(builder.BuildError, "mismatch"):
                builder.download_to_cache(trusted, root)
            self.assertEqual(artifact.read_bytes(), b"tampered")

    def test_download_uses_https_only_curl_and_publishes_verified_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            payload = b"downloaded"
            trusted = source(digest=hashlib.sha256(payload).hexdigest())
            commands = []

            def fake_run(command, **kwargs):
                commands.append(command)
                pathlib.Path(command[command.index("--output") + 1]).write_bytes(payload)
                return subprocess.CompletedProcess(command, 0, "", "")

            with mock.patch.object(builder, "run", side_effect=fake_run):
                result = builder.download_to_cache(trusted, root)
            self.assertEqual(result.read_bytes(), payload)
            self.assertIn("=https", commands[0])
            self.assertIn("--proto-redir", commands[0])

    def test_protected_catalog_removes_end_user_url_and_hash_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            approved = root / "approved.iso"
            approved.write_bytes(b"approved Microsoft media")
            digest = hashlib.sha256(approved.read_bytes()).hexdigest()
            catalog = root / "windows.json"
            catalog.write_text(json.dumps(catalog_document(root, digest)), encoding="utf-8")
            catalog.chmod(0o600)
            cfg = builder.Config.from_catalog(catalog)
            self.assertEqual(cfg.windows_iso.local_path, approved)
            self.assertEqual(cfg.windows_iso.sha256, digest)

    def test_local_approved_iso_is_verified_and_imported_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            approved = root / "approved.iso"
            approved.write_bytes(b"approved")
            artifact = builder.ArtifactSource(
                "Windows ISO", "", hashlib.sha256(b"approved").hexdigest(), (),
                "windows.iso", approved,
            )
            with mock.patch.object(builder, "run") as command:
                cached = builder.download_to_cache(artifact, root / "cache")
            self.assertEqual(cached.read_bytes(), b"approved")
            command.assert_not_called()

    def test_one_time_registration_stages_iso_and_writes_no_replace_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            iso = root / "input.iso"
            iso.write_bytes(b"Microsoft evaluation media")
            digest = hashlib.sha256(iso.read_bytes()).hexdigest()
            catalog = root / "etc" / "windows.json"
            source_dir = root / "sources"
            argv = [
                "--catalog", str(catalog), "register-sources",
                "--windows-iso", str(iso), "--windows-sha256", digest,
                "--image-index", "4", "--image-name", "Windows Server 2022 SERVERDATACENTER",
                "--virtio-url", "https://virtio.example/virtio.iso",
                "--virtio-sha256", "b" * 64, "--virtio-allowed-host", "virtio.example",
                "--cloudbase-url", "https://cloudbase.example/setup.msi",
                "--cloudbase-sha256", "c" * 64,
                "--cloudbase-allowed-host", "cloudbase.example",
                "--approved-by", "test-admin", "--accept-microsoft-evaluation-license",
                "--source-dir", str(source_dir),
            ]
            args = builder.parse_args(argv)
            builder.register_approved_catalog(args)
            document = json.loads(catalog.read_text(encoding="utf-8"))
            staged = pathlib.Path(document["sources"]["windows_iso"]["local_path"])
            self.assertEqual(staged.read_bytes(), iso.read_bytes())
            self.assertEqual(document["sources"]["windows_iso"]["sha256"], digest)
            self.assertEqual(catalog.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(builder.BuildError, "refusing overwrite"):
                builder.register_approved_catalog(args)


class WimTests(unittest.TestCase):
    def _metadata(self, root, *, index="4", name="Windows Server 2022 SERVERDATACENTER", edition="ServerDatacenterEval", install="Server", build="20348"):
        path = root / "wim.xml"
        path.write_text(
            f"""<WIM><IMAGE INDEX="{index}"><NAME>{name}</NAME><WINDOWS><ARCH>9</ARCH><EDITIONID>{edition}</EDITIONID><PRODUCTTYPE>ServerNT</PRODUCTTYPE><INSTALLATIONTYPE>{install}</INSTALLATIONTYPE><VERSION><BUILD>{build}</BUILD></VERSION></WINDOWS></IMAGE></WIM>""",
            encoding="utf-8",
        )
        return path

    def test_exact_server_2022_desktop_image_is_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            cfg = config(root)
            builder.validate_wim_metadata(self._metadata(root), cfg)
            for change in (
                {"index": "3"},
                {"edition": "ServerStandardEval"},
                {"install": "Server Core"},
                {"build": "26100"},
            ):
                with self.assertRaises(builder.BuildError):
                    builder.validate_wim_metadata(self._metadata(root, **change), cfg)


class TemplateTests(unittest.TestCase):
    def test_autounattend_is_valid_and_has_exact_index(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "Autounattend.xml"
            builder.render_autounattend(
                ROOT / "templates" / "Autounattend.xml", output, 4, "OneTime!Password9a"
            )
            text = output.read_text(encoding="utf-8")
            self.assertIn("<Value>4</Value>", text)
            self.assertEqual(text.count("OneTime!Password9a"), 3)
            self.assertNotIn("@@", text)
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)

    def test_packer_exposes_only_loopback_winrm_and_no_rdp(self):
        text = (ROOT / "windows-server-2022.pkr.hcl").read_text(encoding="utf-8")
        self.assertIn('source  = "github.com/hashicorp/qemu"', text)
        self.assertIn('version = "= 1.1.3"', text)
        self.assertIn("hostfwd=tcp:127.0.0.1:", text)
        self.assertIn("restrict=on", text)
        self.assertIn('vnc_bind_address  = "127.0.0.1"', text)
        self.assertNotIn("0.0.0.0", text)
        self.assertNotIn("3389", text)
        self.assertIn('disk_interface   = "virtio"', text)
        self.assertIn('net_device       = "e1000"', text)
        self.assertNotIn('["-device"', text)
        self.assertIn("floppy_files", text)
        self.assertIn("hf-finalize.ps1", text)


class ResourceTests(unittest.TestCase):
    def test_available_memory_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "meminfo"
            path.write_text("MemTotal: 6656000 kB\nMemAvailable: 5242880 kB\n", encoding="ascii")
            self.assertEqual(builder.available_memory_bytes(path), 5 * builder.GIB)

    def test_build_refuses_low_ram_or_disk(self):
        with self.assertRaisesRegex(builder.BuildError, "RAM"):
            builder.validate_resource_limits(4 * builder.GIB, 100 * builder.GIB)
        with self.assertRaisesRegex(builder.BuildError, "disk"):
            builder.validate_resource_limits(6 * builder.GIB, 20 * builder.GIB)

    def test_cleanup_removes_only_named_verified_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            cfg = config(root)
            root.joinpath("cache").mkdir()
            for item in (cfg.windows_iso, cfg.virtio_iso, cfg.cloudbase_msi):
                (cfg.cache_dir / item.cache_name).write_bytes(b"source")
            unrelated = cfg.cache_dir / "keep-me"
            unrelated.write_bytes(b"keep")
            builder.cleanup_cached_sources(cfg)
            self.assertTrue(unrelated.exists())
            self.assertEqual(list(cfg.cache_dir.iterdir()), [unrelated])


class OutputTests(unittest.TestCase):
    def _fake_run(self, command, **kwargs):
        if command[:3] == ["qemu-img", "info", "--output=json"]:
            output = json.dumps({"format": "qcow2", "virtual-size": 48 * builder.GIB})
        elif command[0] == "virt-inspector":
            output = "<product_name>Windows Server 2022</product_name><arch>x86_64</arch>"
        elif command[0] == "virt-ls" and command[-1] == "/Program Files":
            output = "Cloudbase Solutions\nqemu-ga\n"
        elif command[0] == "virt-ls":
            output = "viostor.inf_amd64\nnetkvm.inf_amd64\nvioser.inf_amd64\n"
        elif command[0] == "virt-cat":
            output = "metadata_services=ConfigDriveService\ninject_user_password=true\n"
        else:
            output = ""
        return subprocess.CompletedProcess(command, 0, output, "")

    def test_output_compatibility_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            image = pathlib.Path(directory) / "image.qcow2"
            image.write_bytes(b"qcow2")
            with mock.patch.object(builder, "run", side_effect=self._fake_run):
                builder.verify_output(image)

    def test_publish_is_no_replace_and_manifest_is_linked_last(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source_image = root / "source.qcow2"
            source_image.write_bytes(b"prepared")
            destination = root / "images" / builder.OUTPUT_NAME
            real_link = os.link
            links = []

            def fake_run(command, **kwargs):
                if command[:2] == ["qemu-img", "convert"]:
                    pathlib.Path(command[-1]).write_bytes(source_image.read_bytes())
                return subprocess.CompletedProcess(command, 0, "", "")

            def recording_link(src, dst):
                links.append(pathlib.Path(dst).name)
                return real_link(src, dst)

            with mock.patch.object(builder, "run", side_effect=fake_run), mock.patch.object(
                builder, "verify_output"
            ), mock.patch.object(builder.os, "link", side_effect=recording_link):
                checksum = builder.publish_no_replace(source_image, destination)
            self.assertEqual(links, [builder.OUTPUT_NAME, builder.OUTPUT_NAME + ".sha256"])
            self.assertEqual(checksum, hashlib.sha256(b"prepared").hexdigest())
            original = destination.read_bytes()
            with self.assertRaises(builder.BuildError):
                builder.publish_no_replace(source_image, destination)
            self.assertEqual(destination.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
