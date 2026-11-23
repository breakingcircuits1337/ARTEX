"""Unit tests for PR #18's release artifact rejection rules."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

from release_qualification import (
    TARGETS, QualificationError, release_version, validate_artifacts,
    validate_metadata, validate_package,
)


class ReleaseQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tag = "v1.2.3"

    def make_zip(self, os_name: str, arch: str, *, evil: str | None = None,
                 symlink: bool = False) -> Path:
        prefix = f"artex-1.2.3-{os_name}-{arch}"
        dest = self.root / f"{prefix}.zip"
        binary = "artex.exe" if os_name == "windows" else "artex"
        launcher = "start.bat" if os_name == "windows" else "start.sh"
        with zipfile.ZipFile(dest, "w") as z:
            for filename, data in {
                binary: b"binary",
                launcher: b"echo start",
                "README.md": b"documentation",
                "config.example.json": b"{}",
                "skills/test/SKILL.md": b"fixture",
            }.items():
                z.writestr(f"{prefix}/{filename}", data)
            if evil is not None:
                z.writestr(evil, b"unsafe")
            if symlink:
                info = zipfile.ZipInfo(f"{prefix}/skills/link")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, "../outside")
        return dest

    def all_zips(self) -> None:
        for os_name, arch in TARGETS:
            self.make_zip(os_name, arch)

    def make_metadata(self) -> None:
        lines = []
        for filename in sorted(self.root.glob("*.zip")):
            digest = hashlib.sha256(filename.read_bytes()).hexdigest()
            lines.append(f"{digest}  {filename.name}")
        (self.root / "SHA256SUMS").write_text("\n".join(lines) + "\n")
        (self.root / f"artex-{self.tag}.cdx.json").write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "components": [{"purl": "pkg:golang/example.com/thing@1.0.0"},
                           {"purl": "pkg:npm/example@1.0.0"}]
        }))

    def test_version_policy(self) -> None:
        self.assertEqual(release_version("v1.2.3-rc.1"), "1.2.3-rc.1")
        for invalid in ("main", "1.2.3", "v01.2.3", "v1.2", "v1.2.3+meta", "v1.2.3/evil"):
            with self.subTest(invalid=invalid), self.assertRaises(QualificationError):
                release_version(invalid)

    def test_complete_release(self) -> None:
        self.all_zips()
        self.make_metadata()
        validate_artifacts(self.root, self.tag)
        validate_metadata(self.root, self.tag)

    def test_missing_target_or_unexpected_zip(self) -> None:
        self.all_zips()
        (self.root / "artex-1.2.3-linux-amd64.zip").unlink()
        with self.assertRaises(QualificationError):
            validate_artifacts(self.root, self.tag)
        self.make_zip("linux", "amd64")
        (self.root / "injected.zip").write_bytes(b"bad")
        with self.assertRaises(QualificationError):
            validate_artifacts(self.root, self.tag)

    def test_traversal_and_symlink_rejected(self) -> None:
        path = self.make_zip("linux", "amd64", evil="../escape")
        with self.assertRaises(QualificationError):
            validate_package(path, "1.2.3", "linux", "amd64")
        path = self.make_zip("linux", "amd64", symlink=True)
        with self.assertRaises(QualificationError):
            validate_package(path, "1.2.3", "linux", "amd64")

    def test_checksum_mismatch(self) -> None:
        self.all_zips()
        self.make_metadata()
        original = self.root / "SHA256SUMS"
        original.write_text(original.read_text().replace("a", "b", 1))
        with self.assertRaises(QualificationError):
            validate_metadata(self.root, self.tag)

    def test_missing_npm_sbom_fails(self) -> None:
        self.all_zips()
        self.make_metadata()
        doc = self.root / "artex-v1.2.3.cdx.json"
        doc.write_text(json.dumps({"bomFormat": "CycloneDX",
                                   "components": [{"purl": "pkg:golang/a@1.0"}]}))
        with self.assertRaises(QualificationError):
            validate_metadata(self.root, self.tag)


if __name__ == "__main__":
    unittest.main()
