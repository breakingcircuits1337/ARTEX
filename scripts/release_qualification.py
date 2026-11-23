#!/usr/bin/env python3
"""Fail-closed release artifact and metadata qualification (stdlib only).

The release workflow invokes:
  python3 scripts/release_qualification.py tag --tag v1.2.3
  python3 scripts/release_qualification.py artifacts --tag v1.2.3 --dir dist
  python3 scripts/release_qualification.py metadata --tag v1.2.3 --dir dist

Checks packages before publishing; does not certify the application itself.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

TARGETS = (
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
    ("windows", "amd64"),
)
VERSION_PATTERN = re.compile(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9A-Za-z][0-9A-Za-z-]*)(?:\.(?:0|[1-9A-Za-z][0-9A-Za-z-]*))*)?"
)
MAX_ZIP_MEMBERS = 100_000
MAX_MEMBER_BYTES = 2 << 30
MAX_ZIP_BYTES = 4 << 30


class QualificationError(ValueError):
    """A package fails the release contract."""


def release_version(tag: str) -> str:
    if not VERSION_PATTERN.fullmatch(tag):
        raise QualificationError(
            f"invalid release tag {tag!r}: use vMAJOR.MINOR.PATCH[-prerelease]"
        )
    return tag[1:]


def package_names(tag: str) -> set[str]:
    version = release_version(tag)
    return {f"artex-{version}-{goos}-{arch}.zip" for goos, arch in TARGETS}


def _safe_member(name: str, expected_root: str) -> None:
    if not name or "\\" in name or "\x00" in name or ":" in name or name.startswith("/"):
        raise QualificationError(f"unsafe ZIP entry: {name!r}")
    pieces = PurePosixPath(name).parts
    if not pieces or any(p in {".", ".."} for p in name.rstrip("/").split("/")):
        raise QualificationError(f"ZIP traversal entry: {name!r}")
    if pieces[0] != expected_root or len(pieces) < 2:
        raise QualificationError(f"ZIP entry outside its package root: {name!r}")


def validate_package(path: Path, version: str, goos: str, arch: str) -> None:
    root = f"artex-{version}-{goos}-{arch}"
    executable = "artex.exe" if goos == "windows" else "artex"
    launcher = "start.bat" if goos == "windows" else "start.sh"
    required = {
        f"{root}/{executable}",
        f"{root}/{launcher}",
        f"{root}/config.example.json",
        f"{root}/README.md",
    }
    present: set[str] = set()
    has_skills = False
    total_size = 0
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if not members or len(members) > MAX_ZIP_MEMBERS:
                raise QualificationError(f"invalid entry count in {path.name}")
            for member in members:
                _safe_member(member.filename, root)
                if member.filename in present:
                    raise QualificationError(f"duplicate ZIP entry: {member.filename!r}")
                present.add(member.filename)
                if stat.S_IFMT(member.external_attr >> 16) == stat.S_IFLNK:
                    raise QualificationError(f"ZIP symlink refused: {member.filename!r}")
                if member.file_size > MAX_MEMBER_BYTES:
                    raise QualificationError(f"oversized ZIP member: {member.filename!r}")
                total_size += member.file_size
                if total_size > MAX_ZIP_BYTES:
                    raise QualificationError(f"uncompressed ZIP too large: {path.name}")
                if member.filename.startswith(f"{root}/skills/"):
                    has_skills = True
            if missing := required - present:
                raise QualificationError(f"missing package content in {path.name}: {sorted(missing)}")
            if not has_skills:
                raise QualificationError(f"missing packaged skills in {path.name}")
            binary = archive.getinfo(f"{root}/{executable}")
            if binary.file_size == 0:
                raise QualificationError(f"empty executable in {path.name}")
            if bad := archive.testzip():
                raise QualificationError(f"ZIP CRC failure in {path.name}: {bad}")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise QualificationError(f"unreadable package {path.name}: {exc}") from exc


def validate_artifacts(directory: Path, tag: str) -> None:
    version = release_version(tag)
    expected = package_names(tag)
    found = {p.name for p in directory.glob("*.zip") if p.is_file()}
    if found != expected:
        raise QualificationError(
            f"release ZIP set mismatch: missing={sorted(expected - found)} extra={sorted(found - expected)}"
        )
    for goos, arch in TARGETS:
        validate_package(directory / f"artex-{version}-{goos}-{arch}.zip", version, goos, arch)


def validate_metadata(directory: Path, tag: str) -> None:
    validate_artifacts(directory, tag)
    expected = package_names(tag)
    checksums = directory / "SHA256SUMS"
    if not checksums.is_file():
        raise QualificationError("missing SHA256SUMS")
    seen: set[str] = set()
    for raw in checksums.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\\s]+\.zip)", raw)
        if not match:
            raise QualificationError(f"malformed checksum entry: {raw!r}")
        digest, name = match.groups()
        if name not in expected or name in seen:
            raise QualificationError(f"unexpected/duplicate checksum for {name!r}")
        seen.add(name)
        h = hashlib.sha256()
        with (directory / name).open("rb") as binary:
            for chunk in iter(lambda: binary.read(1024 * 1024), b""):
                h.update(chunk)
        if h.hexdigest() != digest:
            raise QualificationError(f"checksum mismatch for {name}")
    if seen != expected:
        raise QualificationError(f"incomplete checksums: {sorted(expected - seen)}")

    sbom = directory / f"artex-{tag}.cdx.json"
    try:
        data = json.loads(sbom.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise QualificationError(f"missing/invalid CycloneDX SBOM: {exc}") from exc
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        raise QualificationError("SBOM is not a CycloneDX document")
    components = data.get("components", [])
    if not isinstance(components, list):
        raise QualificationError("invalid CycloneDX components array")
    purls = {c.get("purl", "") for c in components if isinstance(c, dict)}
    for ecosystem in ("pkg:golang/", "pkg:npm/"):
        if not any(p.startswith(ecosystem) for p in purls if isinstance(p, str)):
            raise QualificationError(f"SBOM missing {ecosystem} inventory")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("tag", "artifacts", "metadata"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--dir", type=Path, default=Path("dist"))
    args = parser.parse_args(argv)
    try:
        if args.stage == "tag":
            release_version(args.tag)
        elif args.stage == "artifacts":
            validate_artifacts(args.dir, args.tag)
        else:
            validate_metadata(args.dir, args.tag)
    except QualificationError as exc:
        print(f"release qualification failed: {exc}", file=sys.stderr)
        return 1
    print(f"release qualification passed: {args.stage} for {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
