"""Release assembly rejects stale versions and unreviewed source inputs."""
import argparse
import hashlib
import json
import tempfile
import tarfile
import zipfile
import unittest
from pathlib import Path
from unittest.mock import patch

import assemble


class AssemblyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "LICENSE").write_text("engine license")
        license_root = self.root / "packaging" / "licenses"
        license_root.mkdir(parents=True)
        (license_root / "supplements.json").write_text("{}")
        (self.root / "taiji").write_bytes(b"engine binary")
        self.args = argparse.Namespace(target="aarch64-apple-darwin", platform="macos-arm64",
            binary=str(self.root / "taiji"), output=str(self.root / "out"), version="v0.2.0")
        self.metadata = {"workspace_root": str(self.root),
            "packages": [{"id": "taiji", "name": "taiji", "version": "0.2.0", "source": None}],
            "resolve": {"nodes": [{"id": "taiji", "deps": []}]}}
        self.dirty = ""

    def run_command(self, *args):
        if args[:2] == ("cargo", "metadata"):
            return json.dumps(self.metadata)
        if args[:2] == ("git", "status"):
            return self.dirty
        if args[:2] == ("git", "show"):
            return "1700000000"
        if args[:2] == ("git", "rev-parse"):
            return "a" * 40
        if args[:2] == ("rustc", "--version"):
            return "rustc fixture"
        raise AssertionError(args)

    def test_tag_mismatch_writes_nothing(self):
        self.args.version = "v0.1.0"
        with patch.object(assemble, "run", self.run_command), self.assertRaises(ValueError):
            assemble.assemble(self.args)
        self.assertFalse(Path(self.args.output).exists())

    def test_ci_rejects_dirty_source(self):
        self.dirty = " M Cargo.toml"
        with patch.object(assemble, "run", self.run_command), patch.dict(assemble.os.environ,
            {"GITHUB_ACTIONS": "true"}), self.assertRaises(ValueError):
            assemble.assemble(self.args)
        self.assertFalse(Path(self.args.output).exists())

    def test_checksums_bind_every_shipped_file(self):
        with patch.object(assemble, "run", self.run_command):
            assemble.assemble(self.args)
        output = Path(self.args.output)
        manifest = json.loads((output / "VERSION.json").read_text())
        self.assertEqual(manifest["version"], "0.2.0")
        self.assertEqual(manifest["git_sha"], "a" * 40)
        records = dict(line.split("  ")[::-1] for line in
            (output / "SHA256SUMS").read_text().splitlines())
        self.assertEqual(set(records), {p.name for p in output.iterdir()} - {"SHA256SUMS"})
        for name, digest in records.items():
            self.assertEqual(digest, hashlib.sha256((output / name).read_bytes()).hexdigest())

    def test_zip_and_tar_preserve_the_same_platform_directory(self):
        directory = self.root / "taiji-sidecar-windows-x64"
        directory.mkdir()
        (directory / "taiji.exe").write_bytes(b"binary")
        (directory / "SHA256SUMS").write_text("checksum")
        expected = {f"{directory.name}/taiji.exe": b"binary",
                    f"{directory.name}/SHA256SUMS": b"checksum"}
        for extension in ("zip", "tar.gz"):
            destination = self.root / f"sidecar.{extension}"
            assemble.archive_sidecar(directory, destination)
            if extension == "zip":
                with zipfile.ZipFile(destination) as archive:
                    actual = {name: archive.read(name) for name in archive.namelist()}
            else:
                with tarfile.open(destination) as archive:
                    actual = {member.name: archive.extractfile(member).read()
                              for member in archive.getmembers() if member.isfile()}
            self.assertEqual(actual, expected)

    def test_license_paths_cannot_escape_package(self):
        package = self.root / "dependency"
        package.mkdir()
        (package / "LICENSE").symlink_to(self.root / "LICENSE")
        self.assertEqual(assemble.license_files({"manifest_path": str(package / "Cargo.toml"),
            "license_file": "../LICENSE"}), [])


if __name__ == "__main__":
    unittest.main()
