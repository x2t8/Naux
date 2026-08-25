#!/usr/bin/env python3
"""Validate the clock-free S4-WP5 whole-program residual-role contract."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_measurement_boundary as wp4


CONTRACT_MAGIC = "NAUX-S4-RESIDUAL-ROLE\t1"
AUTHORITY_MAGIC = "NAUX-S4-RESIDUAL-ROLE-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-RESIDUAL-ROLE-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-residual-role:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-residual-role:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-residual-role:report:v1\0"
WP4_AUTHORITY_SEAL = "bda4409f32e1afe162b68401529d127cf4a77077df000826823d2660ee4ade26"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("contract-status", "contract-only"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("required-role", "naux-residual"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("artifact", "linker-free-standalone-elf64"),
    ("dataset", "static-n16384-r50"),
    ("frontend", "ordinary-naux-frontend"),
    ("generator", "single-general-pipeline"),
    ("dynamic-work", "preserved"),
    ("runtime-envelope", "no-vm-jit-libc-system-linker"),
)
CONTRACT_ORIGINS = (
    ("01", "surface", "exact-accepted-naux-source"),
    ("02", "specialization-request", "sealed-static-n-and-reps"),
    ("03", "residual-ir", "verified-and-source-bound"),
    ("04", "machine-ir", "verified-lowering"),
    ("05", "target-plan", "x86-64-source-bound"),
    ("06", "native-bytes", "naux-owned-encoding"),
    ("07", "artifact", "direct-elf64-writer"),
)
CONTRACT_WORK = (
    ("01", "allocation", "retained"),
    ("02", "initialization", "exact-n-elements"),
    ("03", "kernel", "exact-n-times-reps-traversal"),
    ("04", "checksum", "exact-oracle-result"),
    ("05", "teardown", "mandatory-before-completion"),
)
CONTRACT_GATES = (
    ("01", "parent-authorities", "required", "exact-wp1-wp2-wp3-wp4"),
    ("02", "source-identity", "required", "ordinary-frontend-no-benchmark-parser"),
    ("03", "specialization", "required", "explicit-sealed-n-and-reps"),
    (
        "04",
        "work-preservation",
        "required",
        "allocation-init-kernel-checksum-teardown",
    ),
    ("05", "generator-generality", "required", "one-pipeline-four-kernels"),
    (
        "06",
        "artifact-sovereignty",
        "required",
        "no-vm-jit-libc-system-linker",
    ),
    ("07", "fresh-process-parity", "required", "four-exact-results-no-fallback"),
    (
        "08",
        "independent-replay",
        "required",
        "source-residual-plan-bytes-elf-result",
    ),
)
CONTRACT_FORBIDDEN = (
    ("01", "trace-role-substitution"),
    ("02", "direct-oracle-literal"),
    ("03", "whole-program-precomputation"),
    ("04", "closed-form-replacement"),
    ("05", "lookup-table-trivialization"),
    ("06", "kernel-name-dispatch"),
    ("07", "per-kernel-native-template"),
    ("08", "copied-reference-loop"),
    ("09", "dynamic-dependency"),
    ("10", "fallback-deopt-side-exit-interpreter-entry"),
)
CONTRACT_BLOCKERS = (
    ("01", "residual-generator-unavailable"),
    ("02", "four-artifact-replay-unavailable"),
    ("03", "untimed-role-admission-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP5"),
    ("authority-id", "s4-whole-program-residual-role-v1"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("file-count", "6"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-residual-role.yml",
    "distribution/s4-performance/WP5-NONCLAIMS.md",
    "distribution/s4-performance/WP5-README.md",
    "distribution/s4-performance/WP5-RESIDUAL-ROLE.tsv",
    "scripts/s4_residual_role.py",
    "scripts/tests/test_s4_residual_role.py",
)


class ResidualRoleError(RuntimeError):
    """A fail-closed S4-WP5 residual-role error."""


@dataclass(frozen=True)
class ResidualRoleContract:
    metadata: tuple[tuple[str, str], ...]
    origins: tuple[tuple[str, str, str], ...]
    work: tuple[tuple[str, str, str], ...]
    gates: tuple[tuple[str, str, str, str], ...]
    forbidden: tuple[tuple[str, str], ...]
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
    parent: tuple[str, str, str]
    files: tuple[FileRecord, ...]
    seal: str


@dataclass(frozen=True)
class Admission:
    contract: ResidualRoleContract
    authority: Authority
    report: bytes
    report_root: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_canonical(path: Path, *, limit: int = 1_000_000) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ResidualRoleError(f"cannot read S4-WP5 input: {path}") from error
    if not raw or len(raw) > limit or not raw.endswith(b"\n"):
        raise ResidualRoleError(f"S4-WP5 input has invalid extent: {path}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ResidualRoleError(f"S4-WP5 input is not UTF-8: {path}") from error
    if "\r" in text or "\x00" in text:
        raise ResidualRoleError(f"S4-WP5 input is not canonical LF text: {path}")
    lines = text.splitlines()
    if any(not line for line in lines):
        raise ResidualRoleError(f"blank S4-WP5 row is forbidden: {path}")
    return lines


def _sealed_lines(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    lines = _read_canonical(path)
    if not lines or lines[0] != magic or len(lines) < 3:
        raise ResidualRoleError(f"unsupported S4-WP5 schema: {path}")
    if not lines[-1].startswith("seal\t") or any(
        line.startswith("seal\t") for line in lines[:-1]
    ):
        raise ResidualRoleError(f"S4-WP5 terminal seal is missing or duplicated: {path}")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise ResidualRoleError(f"invalid S4-WP5 seal: {path}")
    body = "".join(f"{line}\n" for line in lines[:-1]).encode()
    if _sha256(domain + body) != fields[1]:
        raise ResidualRoleError(f"S4-WP5 seal mismatch: {path}")
    return lines[1:-1], fields[1]


def _parse_rows(
    lines: list[str], tag: str, width: int, count: int
) -> tuple[tuple[str, ...], ...]:
    if len(lines) != count:
        raise ResidualRoleError(f"unexpected S4-WP5 {tag} row count")
    rows: list[tuple[str, ...]] = []
    for line in lines:
        fields = line.split("\t")
        if len(fields) != width or fields[0] != tag:
            raise ResidualRoleError(f"invalid S4-WP5 {tag} row")
        rows.append(tuple(fields[1:]))
    return tuple(rows)


def parse_contract(path: Path) -> ResidualRoleContract:
    lines, seal = _sealed_lines(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    counts = (
        len(CONTRACT_METADATA),
        len(CONTRACT_ORIGINS),
        len(CONTRACT_WORK),
        len(CONTRACT_GATES),
        len(CONTRACT_FORBIDDEN),
        len(CONTRACT_BLOCKERS),
    )
    if len(lines) != sum(counts):
        raise ResidualRoleError("unexpected S4-WP5 contract row count")
    cursor = 0
    metadata = _parse_rows(lines[cursor : cursor + counts[0]], "meta", 3, counts[0])
    cursor += counts[0]
    origins = _parse_rows(lines[cursor : cursor + counts[1]], "origin", 4, counts[1])
    cursor += counts[1]
    work = _parse_rows(lines[cursor : cursor + counts[2]], "work", 4, counts[2])
    cursor += counts[2]
    gates = _parse_rows(lines[cursor : cursor + counts[3]], "gate", 5, counts[3])
    cursor += counts[3]
    forbidden = _parse_rows(
        lines[cursor : cursor + counts[4]], "forbid", 3, counts[4]
    )
    cursor += counts[4]
    blockers = _parse_rows(lines[cursor:], "blocker", 3, counts[5])
    expected = (
        CONTRACT_METADATA,
        CONTRACT_ORIGINS,
        CONTRACT_WORK,
        CONTRACT_GATES,
        CONTRACT_FORBIDDEN,
        CONTRACT_BLOCKERS,
    )
    if (metadata, origins, work, gates, forbidden, blockers) != expected:
        raise ResidualRoleError("unexpected S4-WP5 residual-role contract")
    return ResidualRoleContract(
        metadata, origins, work, gates, forbidden, blockers, seal
    )


def _safe_path(value: str) -> None:
    if not PATH_RE.fullmatch(value):
        raise ResidualRoleError("invalid S4-WP5 authority path")
    parsed = Path(value)
    if parsed.is_absolute() or "." in parsed.parts or ".." in parsed.parts:
        raise ResidualRoleError("traversing S4-WP5 authority path")


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed_lines(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    expected_rows = len(AUTHORITY_METADATA) + 2 + len(EXPECTED_FILES)
    if len(lines) != expected_rows:
        raise ResidualRoleError("unexpected S4-WP5 authority row count")
    metadata = _parse_rows(
        lines[: len(AUTHORITY_METADATA)], "meta", 3, len(AUTHORITY_METADATA)
    )
    if metadata != AUTHORITY_METADATA:
        raise ResidualRoleError("unexpected S4-WP5 authority metadata")
    cursor = len(AUTHORITY_METADATA)
    component = tuple(lines[cursor].split("\t"))
    if component != (
        "component",
        "residual-role-contract",
        "distribution/s4-performance/WP5-RESIDUAL-ROLE.tsv",
        contract_seal,
    ):
        raise ResidualRoleError("unexpected S4-WP5 contract component")
    cursor += 1
    parent = tuple(lines[cursor].split("\t"))
    expected_parent = (
        "parent",
        "measurement-boundary-authority",
        "distribution/s4-performance/WP4-AUTHORITY.tsv",
        WP4_AUTHORITY_SEAL,
    )
    if parent != expected_parent:
        raise ResidualRoleError("unexpected S4-WP5 parent authority")
    cursor += 1
    files: list[FileRecord] = []
    for line in lines[cursor:]:
        fields = line.split("\t")
        if len(fields) != 5 or fields[0] != "file":
            raise ResidualRoleError("invalid S4-WP5 file row")
        if not MODE_RE.fullmatch(fields[1]) or not UINT_RE.fullmatch(fields[2]):
            raise ResidualRoleError("invalid S4-WP5 file metadata")
        if not HASH_RE.fullmatch(fields[3]):
            raise ResidualRoleError("invalid S4-WP5 file hash")
        _safe_path(fields[4])
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise ResidualRoleError("unexpected S4-WP5 file inventory")
    return Authority(metadata, parent[1:], tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        try:
            info = path.lstat()
        except OSError as error:
            raise ResidualRoleError(f"missing bound S4-WP5 file: {record.path}") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ResidualRoleError(f"bound S4-WP5 path is not regular: {record.path}")
        raw = path.read_bytes()
        mode = stat.S_IFREG | stat.S_IMODE(info.st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise ResidualRoleError(f"bound S4-WP5 file drifted: {record.path}")


def _verify_contract_only(root: Path) -> None:
    workflow = (root / ".github/workflows/s4-residual-role.yml").read_text(
        encoding="utf-8"
    )
    required = (
        "python3 scripts/s4_residual_role.py",
        "python3 -m unittest scripts.tests.test_s4_residual_role",
    )
    if any(command not in workflow for command in required):
        raise ResidualRoleError("S4-WP5 workflow does not replay its role contract")
    forbidden = (
        "cargo run",
        "cargo build",
        "benchrt",
        "hyperfine",
        "/usr/bin/time",
        "perf stat",
        "time python",
        "date +",
    )
    if any(command in workflow for command in forbidden):
        raise ResidualRoleError("build, execution, or clock entered the contract-only workflow")
    expected = {
        "WP5-AUTHORITY.tsv",
        "WP5-NONCLAIMS.md",
        "WP5-README.md",
        "WP5-RESIDUAL-ROLE.tsv",
    }
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP5-*")
        if path.is_file()
    }
    if actual != expected:
        raise ResidualRoleError("unexpected S4-WP5 result or distribution artifact")


def validate(root: Path) -> Admission:
    root = root.resolve()
    parent = wp4.validate(root)
    if parent.authority.seal != WP4_AUTHORITY_SEAL:
        raise ResidualRoleError("accepted S4-WP4 authority drifted")
    contract = parse_contract(
        root / "distribution/s4-performance/WP5-RESIDUAL-ROLE.tsv"
    )
    authority = parse_authority(
        root / "distribution/s4-performance/WP5-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_contract_only(root)
    lines = [
        REPORT_MAGIC,
        "contract-status\tcontract-only",
        "claim-status\tnot-admitted",
        "timing-status\tforbidden",
        f"wp4-authority-seal\t{WP4_AUTHORITY_SEAL}",
        f"wp5-contract-seal\t{contract.seal}",
        f"wp5-authority-seal\t{authority.seal}",
        f"files\t{len(authority.files)}",
    ]
    lines.extend(f"blocker\t{ordinal}\t{name}" for ordinal, name in contract.blockers)
    body = "".join(f"{line}\n" for line in lines).encode()
    report_root = _sha256(REPORT_DOMAIN + body)
    report = body + f"report-root\t{report_root}\n".encode()
    return Admission(contract, authority, report, report_root)


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
    except (ResidualRoleError, wp4.BoundaryError, OSError) as error:
        print(f"S4 residual role rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
