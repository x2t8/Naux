#!/usr/bin/env python3
"""Verify the sealed S2 Linguist surface without npm or Ruby dependencies."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


DOMAIN = b"NAUX:s2-linguist-surface:v1\0"
MAGIC = "NAUX-S2-LINGUIST-SURFACE\t1"
EXPECTED_METADATA = {
    "repository": "https://github.com/x2t8/naux-grammar.git",
    "tag": "v0.1.2",
    "tag-object": "36e5eae4ddfe6db35d5a268cf36032cc4fcd12e1",
    "commit": "124d72cc8ae4fdaef6413ef94e6cf895fb294a55",
    "tree": "34f0f17115a5367c6ca20f445de3bd3fef835143",
    "package-version": "0.1.2",
    "language": "NAUX",
    "extension": ".nx",
    "tm-scope": "source.naux",
    "color": "#FF304D",
    "public-builtins": "71",
}
METADATA_ORDER = tuple(EXPECTED_METADATA)


class SurfaceError(RuntimeError):
    """A fail-closed Linguist-surface admission error."""


@dataclass(frozen=True)
class FileRecord:
    mode: int
    size: int
    sha256: str
    path: str


@dataclass(frozen=True)
class SurfaceLock:
    metadata: dict[str, str]
    files: tuple[FileRecord, ...]
    seal: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_lock(path: Path) -> SurfaceLock:
    raw = path.read_bytes()
    if not raw.endswith(b"\n"):
        raise SurfaceError("surface lock must end with one LF")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SurfaceError("surface lock must be UTF-8") from error
    if "\r" in text:
        raise SurfaceError("surface lock must use LF line endings")

    lines = text.splitlines()
    if not lines or lines[0] != MAGIC:
        raise SurfaceError("unsupported surface-lock schema")

    cursor = 1
    metadata: dict[str, str] = {}
    for expected_key in METADATA_ORDER:
        fields = lines[cursor].split("\t")
        if len(fields) != 2 or fields[0] != expected_key:
            raise SurfaceError(f"surface metadata order drift at {expected_key}")
        metadata[fields[0]] = fields[1]
        cursor += 1

    count_fields = lines[cursor].split("\t")
    if len(count_fields) != 2 or count_fields[0] != "files":
        raise SurfaceError("surface lock is missing its file count")
    try:
        file_count = int(count_fields[1])
    except ValueError as error:
        raise SurfaceError("surface file count is not an integer") from error
    if file_count <= 0:
        raise SurfaceError("surface file count must be positive")
    cursor += 1

    records: list[FileRecord] = []
    for _ in range(file_count):
        fields = lines[cursor].split("\t")
        if len(fields) != 5 or fields[0] != "file":
            raise SurfaceError("malformed surface file record")
        try:
            mode = int(fields[1], 8)
            size = int(fields[2])
        except ValueError as error:
            raise SurfaceError("invalid surface file mode or size") from error
        if mode != 0o644 or size < 0:
            raise SurfaceError("surface files require mode 0644 and nonnegative size")
        digest, relative = fields[3], fields[4]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise SurfaceError("invalid surface file SHA-256")
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts or relative != candidate.as_posix():
            raise SurfaceError("surface file path is not canonical and relative")
        records.append(FileRecord(mode, size, digest, relative))
        cursor += 1

    if cursor >= len(lines):
        raise SurfaceError("surface lock has no seal")
    seal_fields = lines[cursor].split("\t")
    if len(seal_fields) != 2 or seal_fields[0] != "seal" or cursor + 1 != len(lines):
        raise SurfaceError("surface lock has a malformed or non-final seal")
    seal = seal_fields[1]
    if len(seal) != 64 or any(c not in "0123456789abcdef" for c in seal):
        raise SurfaceError("invalid surface seal")

    body = "".join(f"{line}\n" for line in lines[:cursor]).encode("utf-8")
    if _sha256(DOMAIN + body) != seal:
        raise SurfaceError("surface lock seal mismatch")
    if metadata != EXPECTED_METADATA:
        raise SurfaceError("surface metadata differs from the admitted v0.1.2 identity")

    paths = [record.path for record in records]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise SurfaceError("surface file inventory must be unique and byte-sorted")
    return SurfaceLock(metadata, tuple(records), seal)


def _inventory(root: Path) -> tuple[str, ...]:
    return tuple(
        sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and ".git" not in path.relative_to(root).parts
        )
    )


def verify_files(root: Path, lock: SurfaceLock) -> None:
    if not root.is_dir():
        raise SurfaceError(f"surface root is not a directory: {root}")
    expected_paths = tuple(record.path for record in lock.files)
    actual_paths = _inventory(root)
    if actual_paths != expected_paths:
        missing = sorted(set(expected_paths) - set(actual_paths))
        extra = sorted(set(actual_paths) - set(expected_paths))
        raise SurfaceError(f"surface inventory drift; missing={missing}, extra={extra}")

    for record in lock.files:
        path = root / record.path
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise SurfaceError(f"surface member is not a regular file: {record.path}")
        mode = stat.S_IMODE(info.st_mode)
        if mode != record.mode:
            raise SurfaceError(f"surface file mode drift: {record.path}")
        data = path.read_bytes()
        if len(data) != record.size or _sha256(data) != record.sha256:
            raise SurfaceError(f"surface file content drift: {record.path}")


def verify_identity(root: Path, lock: SurfaceLock) -> None:
    package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    identity = json.loads((root / "linguist-language.json").read_text(encoding="utf-8"))
    expected = lock.metadata
    checks = {
        "package-version": package.get("version"),
        "language": identity.get("language"),
        "extension": identity.get("extensions", [None])[0],
        "tm-scope": identity.get("tmScope"),
        "color": identity.get("color"),
    }
    for field, actual in checks.items():
        if actual != expected[field]:
            raise SurfaceError(f"surface identity drift: {field}")
    if package.get("dependencies") is not None or package.get("devDependencies") is not None:
        raise SurfaceError("canonical grammar must remain dependency-free")
    if identity.get("status") != "candidate-not-submitted":
        raise SurfaceError("external Linguist acceptance must not be inferred locally")


def _git(checkout: Path, revision: str) -> str:
    completed = subprocess.run(
        ["git", "-C", os.fspath(checkout), "rev-parse", revision],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise SurfaceError(
            f"cannot resolve {revision} in canonical checkout: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def verify_canonical_checkout(checkout: Path, lock: SurfaceLock) -> None:
    expected = lock.metadata
    resolutions = {
        "tag-object": _git(checkout, f"{expected['tag']}^{{tag}}"),
        "commit": _git(checkout, f"{expected['tag']}^{{}}"),
        "tree": _git(checkout, f"{expected['tag']}^{{tree}}"),
    }
    for field, actual in resolutions.items():
        if actual != expected[field]:
            raise SurfaceError(f"canonical Git identity drift: {field}")
    verify_files(checkout, lock)


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lock",
        type=Path,
        default=repo_root / "distribution/s2-preview/LINGUIST-SURFACE.tsv",
        help="sealed surface lock",
    )
    parser.add_argument(
        "--surface",
        type=Path,
        default=repo_root / "vscode/naux-lang",
        help="monorepo grammar mirror",
    )
    parser.add_argument(
        "--canonical-checkout",
        type=Path,
        help="optional checkout containing the exact annotated canonical tag",
    )
    args = parser.parse_args(argv)

    try:
        lock = parse_lock(args.lock)
        verify_files(args.surface, lock)
        verify_identity(args.surface, lock)
        if args.canonical_checkout is not None:
            verify_canonical_checkout(args.canonical_checkout, lock)
    except (OSError, json.JSONDecodeError, SurfaceError) as error:
        print(f"S2 Linguist surface: FAIL: {error}", file=sys.stderr)
        return 1

    print(
        "S2 Linguist surface: PASS "
        f"({lock.metadata['tag']} {lock.metadata['commit']}; "
        f"{len(lock.files)} files; seal {lock.seal})"
    )
    if args.canonical_checkout is None:
        print("Canonical remote replay: NOT REQUESTED")
    else:
        print("Canonical tag/tree and byte-for-byte mirror replay: PASS")
    print("Upstream Linguist adoption/acceptance: NOT CLAIMED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
