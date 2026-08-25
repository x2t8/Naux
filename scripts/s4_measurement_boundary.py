#!/usr/bin/env python3
"""Validate the clock-free S4-WP4 controlled measurement boundary."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_native_carrier as wp3


BOUNDARY_MAGIC = "NAUX-S4-MEASUREMENT-BOUNDARY\t1"
AUTHORITY_MAGIC = "NAUX-S4-MEASUREMENT-BOUNDARY-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-MEASUREMENT-BOUNDARY-REPORT\t1"
BOUNDARY_DOMAIN = b"NAUX:s4-measurement-boundary:policy:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-measurement-boundary:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-measurement-boundary:report:v1\0"
WP1_AUTHORITY_SEAL = "b23533c4e96ec9e3b66482e96b79fdeb5985c823ce012d827e69eb1c14a4b659"
WP2_AUTHORITY_SEAL = "0361c1e0d90bc3ba8d9a1e0bead7466bd71be3e3a723d605606730144ae7db6a"
WP3_AUTHORITY_SEAL = "7a853a68da91a4d41f3fe6f7b9e9e21dd254a4d4ac36b248007e506bd046c9ab"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")

BOUNDARY_METADATA = (
    ("policy-version", "1.0.0"),
    ("claim-status", "not-admitted"),
    ("available-naux-role", "naux-trace-carrier-observation"),
    ("required-naux-role", "naux-residual"),
    ("runtime-region", "allocation-initialization-kernel-checksum-teardown"),
    ("minimum-warmup-ms", "100"),
    ("measured-samples", "30"),
    ("sample-policy", "retain-all-in-collection-order"),
    ("maximum-cv-percent", "5"),
)
BOUNDARY_GATES = (
    ("01", "parent-authorities", "required", "exact-wp1-wp2-wp3"),
    ("02", "semantic-parity", "required", "every-sample"),
    (
        "03",
        "native-path",
        "required",
        "zero-fallback-deopt-side-exit-guard-failure-interpreter-index",
    ),
    (
        "04",
        "host-control",
        "required",
        "clean-sha-affinity-performance-governor-turbo-off-monotonic-clock",
    ),
    (
        "05",
        "role-completeness",
        "required",
        "naux-residual-c-generic-c-specialized",
    ),
    ("06", "raw-samples", "required", "ordered-complete-no-drop-no-retry"),
    (
        "07",
        "cost-separation",
        "required",
        "compile-specialize-startup-runtime-memory-code-size",
    ),
    ("08", "independent-replay", "required", "structure-arithmetic-seals"),
)
BOUNDARY_BLOCKERS = (
    ("01", "naux-residual-unavailable"),
    ("02", "controlled-host-unavailable"),
    ("03", "measurement-runner-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP4"),
    ("authority-id", "s4-controlled-measurement-boundary-v1"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("file-count", "6"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-measurement-boundary.yml",
    "distribution/s4-performance/WP4-BOUNDARY.tsv",
    "distribution/s4-performance/WP4-NONCLAIMS.md",
    "distribution/s4-performance/WP4-README.md",
    "scripts/s4_measurement_boundary.py",
    "scripts/tests/test_s4_measurement_boundary.py",
)
EXPECTED_PARENTS = (
    (
        "benchmark-authority",
        "distribution/s4-performance/AUTHORITY.tsv",
        WP1_AUTHORITY_SEAL,
    ),
    (
        "reference-authority",
        "distribution/s4-performance/WP2-AUTHORITY.tsv",
        WP2_AUTHORITY_SEAL,
    ),
    (
        "native-carrier-authority",
        "distribution/s4-performance/WP3-AUTHORITY.tsv",
        WP3_AUTHORITY_SEAL,
    ),
)


class BoundaryError(RuntimeError):
    """A fail-closed S4-WP4 boundary error."""


@dataclass(frozen=True)
class Boundary:
    metadata: tuple[tuple[str, str], ...]
    gates: tuple[tuple[str, str, str, str], ...]
    blockers: tuple[tuple[str, str], ...]
    seal: str


@dataclass(frozen=True)
class FileRecord:
    mode: int
    size: int
    sha256: str
    path: str


@dataclass(frozen=True)
class Authority:
    metadata: tuple[tuple[str, str], ...]
    parents: tuple[tuple[str, str, str], ...]
    files: tuple[FileRecord, ...]
    seal: str


@dataclass(frozen=True)
class Admission:
    boundary: Boundary
    authority: Authority
    report: bytes
    report_root: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_canonical(path: Path, *, limit: int = 1_000_000) -> tuple[bytes, list[str]]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise BoundaryError(f"cannot read S4-WP4 input: {path}") from error
    if not raw or len(raw) > limit or not raw.endswith(b"\n"):
        raise BoundaryError(f"S4-WP4 input has invalid extent: {path}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BoundaryError(f"S4-WP4 input is not UTF-8: {path}") from error
    if "\r" in text or "\x00" in text:
        raise BoundaryError(f"S4-WP4 input is not canonical LF text: {path}")
    lines = text.splitlines()
    if any(not line for line in lines):
        raise BoundaryError(f"blank S4-WP4 row is forbidden: {path}")
    return raw, lines


def _sealed_lines(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    _raw, lines = _read_canonical(path)
    if not lines or lines[0] != magic or len(lines) < 3:
        raise BoundaryError(f"unsupported S4-WP4 schema: {path}")
    if not lines[-1].startswith("seal\t") or any(
        line.startswith("seal\t") for line in lines[:-1]
    ):
        raise BoundaryError(f"S4-WP4 terminal seal is missing or duplicated: {path}")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise BoundaryError(f"invalid S4-WP4 seal: {path}")
    body = "".join(f"{line}\n" for line in lines[:-1]).encode()
    if _sha256(domain + body) != fields[1]:
        raise BoundaryError(f"S4-WP4 seal mismatch: {path}")
    return lines[1:-1], fields[1]


def parse_boundary(path: Path) -> Boundary:
    lines, seal = _sealed_lines(path, BOUNDARY_MAGIC, BOUNDARY_DOMAIN)
    expected = len(BOUNDARY_METADATA) + len(BOUNDARY_GATES) + len(BOUNDARY_BLOCKERS)
    if len(lines) != expected:
        raise BoundaryError("unexpected S4-WP4 boundary row count")
    metadata: list[tuple[str, str]] = []
    for line in lines[: len(BOUNDARY_METADATA)]:
        fields = line.split("\t")
        if len(fields) != 3 or fields[0] != "meta":
            raise BoundaryError("invalid S4-WP4 metadata row")
        metadata.append((fields[1], fields[2]))
    if tuple(metadata) != BOUNDARY_METADATA:
        raise BoundaryError("unexpected S4-WP4 metadata")
    gate_start = len(BOUNDARY_METADATA)
    gates: list[tuple[str, str, str, str]] = []
    for line in lines[gate_start : gate_start + len(BOUNDARY_GATES)]:
        fields = line.split("\t")
        if len(fields) != 5 or fields[0] != "gate":
            raise BoundaryError("invalid S4-WP4 gate row")
        gates.append((fields[1], fields[2], fields[3], fields[4]))
    if tuple(gates) != BOUNDARY_GATES:
        raise BoundaryError("unexpected S4-WP4 gates")
    blockers: list[tuple[str, str]] = []
    for line in lines[gate_start + len(BOUNDARY_GATES) :]:
        fields = line.split("\t")
        if len(fields) != 3 or fields[0] != "blocker":
            raise BoundaryError("invalid S4-WP4 blocker row")
        blockers.append((fields[1], fields[2]))
    if tuple(blockers) != BOUNDARY_BLOCKERS:
        raise BoundaryError("unexpected S4-WP4 blockers")
    return Boundary(tuple(metadata), tuple(gates), tuple(blockers), seal)


def _safe_path(value: str) -> None:
    if not PATH_RE.fullmatch(value):
        raise BoundaryError("invalid S4-WP4 authority path")
    parsed = Path(value)
    if parsed.is_absolute() or "." in parsed.parts or ".." in parsed.parts:
        raise BoundaryError("traversing S4-WP4 authority path")


def parse_authority(path: Path, boundary_seal: str) -> Authority:
    lines, seal = _sealed_lines(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    expected_rows = len(AUTHORITY_METADATA) + 1 + len(EXPECTED_PARENTS) + len(EXPECTED_FILES)
    if len(lines) != expected_rows:
        raise BoundaryError("unexpected S4-WP4 authority row count")
    metadata: list[tuple[str, str]] = []
    for line in lines[: len(AUTHORITY_METADATA)]:
        fields = line.split("\t")
        if len(fields) != 3 or fields[0] != "meta":
            raise BoundaryError("invalid S4-WP4 authority metadata row")
        metadata.append((fields[1], fields[2]))
    if tuple(metadata) != AUTHORITY_METADATA:
        raise BoundaryError("unexpected S4-WP4 authority metadata")
    cursor = len(AUTHORITY_METADATA)
    component = lines[cursor].split("\t")
    if tuple(component) != (
        "component",
        "measurement-boundary",
        "distribution/s4-performance/WP4-BOUNDARY.tsv",
        boundary_seal,
    ):
        raise BoundaryError("unexpected S4-WP4 boundary component")
    cursor += 1
    parents: list[tuple[str, str, str]] = []
    for line in lines[cursor : cursor + len(EXPECTED_PARENTS)]:
        fields = line.split("\t")
        if len(fields) != 4 or fields[0] != "parent":
            raise BoundaryError("invalid S4-WP4 parent row")
        parents.append((fields[1], fields[2], fields[3]))
    if tuple(parents) != EXPECTED_PARENTS:
        raise BoundaryError("unexpected S4-WP4 parent authorities")
    cursor += len(EXPECTED_PARENTS)
    files: list[FileRecord] = []
    for line in lines[cursor:]:
        fields = line.split("\t")
        if len(fields) != 5 or fields[0] != "file":
            raise BoundaryError("invalid S4-WP4 file row")
        if not MODE_RE.fullmatch(fields[1]) or not UINT_RE.fullmatch(fields[2]):
            raise BoundaryError("invalid S4-WP4 file metadata")
        if not HASH_RE.fullmatch(fields[3]):
            raise BoundaryError("invalid S4-WP4 file hash")
        _safe_path(fields[4])
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise BoundaryError("unexpected S4-WP4 file inventory")
    return Authority(tuple(metadata), tuple(parents), tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        try:
            info = path.lstat()
        except OSError as error:
            raise BoundaryError(f"missing bound S4-WP4 file: {record.path}") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise BoundaryError(f"bound S4-WP4 path is not a regular file: {record.path}")
        raw = path.read_bytes()
        actual_mode = stat.S_IFREG | stat.S_IMODE(info.st_mode)
        if actual_mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise BoundaryError(f"bound S4-WP4 file drifted: {record.path}")


def _verify_clock_free_boundary(root: Path) -> None:
    workflow = (root / ".github/workflows/s4-measurement-boundary.yml").read_text(
        encoding="utf-8"
    )
    required = (
        "python3 scripts/s4_measurement_boundary.py",
        "python3 -m unittest scripts.tests.test_s4_measurement_boundary",
    )
    if any(command not in workflow for command in required):
        raise BoundaryError("S4-WP4 workflow does not replay its static boundary")
    forbidden = (
        "cargo run",
        "benchrt",
        "hyperfine",
        "/usr/bin/time",
        "perf stat",
        "time python",
        "date +",
    )
    if any(command in workflow for command in forbidden):
        raise BoundaryError("clock or benchmark execution entered the S4-WP4 workflow")
    expected_distribution = {
        "WP4-AUTHORITY.tsv",
        "WP4-BOUNDARY.tsv",
        "WP4-NONCLAIMS.md",
        "WP4-README.md",
    }
    actual_distribution = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP4-*")
        if path.is_file()
    }
    if actual_distribution != expected_distribution:
        raise BoundaryError("unexpected S4-WP4 result or distribution artifact")


def validate(root: Path) -> Admission:
    root = root.resolve()
    parent = wp3.validate(root)
    if parent.authority.seal != WP3_AUTHORITY_SEAL:
        raise BoundaryError("accepted S4-WP3 authority drifted")
    boundary = parse_boundary(root / "distribution/s4-performance/WP4-BOUNDARY.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP4-AUTHORITY.tsv", boundary.seal
    )
    _verify_files(root, authority)
    _verify_clock_free_boundary(root)
    lines = [
        REPORT_MAGIC,
        "claim-status\tnot-admitted",
        "timing-status\tforbidden",
        f"wp1-authority-seal\t{WP1_AUTHORITY_SEAL}",
        f"wp2-authority-seal\t{WP2_AUTHORITY_SEAL}",
        f"wp3-authority-seal\t{WP3_AUTHORITY_SEAL}",
        f"wp4-boundary-seal\t{boundary.seal}",
        f"wp4-authority-seal\t{authority.seal}",
        f"files\t{len(authority.files)}",
    ]
    lines.extend(f"blocker\t{ordinal}\t{name}" for ordinal, name in boundary.blockers)
    body = "".join(f"{line}\n" for line in lines).encode()
    report_root = _sha256(REPORT_DOMAIN + body)
    report = body + f"report-root\t{report_root}\n".encode()
    return Admission(boundary, authority, report, report_root)


def _default_root() -> Path:
    return Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=_default_root())
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        admission = validate(args.root)
        if args.report is None:
            sys.stdout.buffer.write(admission.report)
        else:
            args.report.write_bytes(admission.report)
    except (BoundaryError, wp3.CarrierError, OSError) as error:
        print(f"S4 measurement boundary rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
