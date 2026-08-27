#!/usr/bin/env python3
"""Validate or replay the clock-free S4-WP7D threshold-candidate law."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_benchmark_authority as wp1
import s4_measurement_evidence as wp7a
import s4_measurement_runner as wp7c


CONTRACT_MAGIC = "NAUX-S4-THRESHOLD-EVALUATOR-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-THRESHOLD-EVALUATOR-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-THRESHOLD-EVALUATOR-REPORT\t1"
CANDIDATE_MAGIC = "NAUX-S4-THRESHOLD-CANDIDATE\t1"
CONTRACT_DOMAIN = b"NAUX:s4-threshold-evaluator:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-threshold-evaluator:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-threshold-evaluator:report:v1\0"
CANDIDATE_DOMAIN = b"NAUX:s4-threshold-evaluator:candidate:v1\0"
BINARY_DOMAIN = b"NAUX:s4-measurement-runner:role-binary:v1\0"
TOOLCHAIN_DOMAIN = b"NAUX:s4-measurement-runner:toolchain:v1\0"
BUNDLE_DOMAIN = b"NAUX:s4-measurement-runner:bundle:v1\0"
SESSION_DOMAIN = b"NAUX:s4-measurement-runner:session:v1\0"
TOOLCHAIN_RECEIPT_DOMAIN = b"NAUX:s4-measurement-runner:toolchain-receipt:v1\0"
WP1_AUTHORITY_SEAL = "b23533c4e96ec9e3b66482e96b79fdeb5985c823ce012d827e69eb1c14a4b659"
WP7A_AUTHORITY_SEAL = "7e10bc03b30b532f05e67c6f6d3ce80d7430125bcae7b9e3824c86cfc233f0bc"
WP7C_AUTHORITY_SEAL = "6c2fb288d7a0012eacc5e6aff4ad49aaff5e218367dd95776c0a470ec95ece7b"
WP7B_NAUX_AUTHORITY_SEAL = "7b9ab600dbb1acc87ff7a4084dc0355b85a69c7cdf967ee072d0f668eb3c0c63"
WP7B_C_AUTHORITY_SEAL = "240bceed62f9ab98b792f2308800df778ce5c35596139349d2a8c03827d63588"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:600|644|700|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
POSITIVE_RE = re.compile(r"[1-9][0-9]*\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-benchmark-authority", WP1_AUTHORITY_SEAL),
    ("parent-evidence-law", WP7A_AUTHORITY_SEAL),
    ("parent-runner-authority", WP7C_AUTHORITY_SEAL),
    ("status", "threshold-evaluator-structurally-admitted"),
    ("input", "exact-wp7c-bundle-v1"),
    ("clock-policy", "forbidden"),
    ("execution-policy", "forbidden"),
    ("claim-status", "not-admitted"),
    ("variance-policy", "all-twelve-statistics-pass"),
    ("arithmetic", "exact-integer-rational-cross-products"),
    ("residual-max-specialized-ratio", "11/10"),
    ("residual-min-generic-speedup", "5/4"),
    ("intersection-policy", "same-kernel-must-pass-both-thresholds"),
    ("result", "threshold-candidate-only"),
    ("target", "x86_64-unknown-linux-gnu"),
)
CONTRACT_GATES = (
    ("01", "bundle-root", "required", "exact-wp7c-manifest-and-inventory"),
    ("02", "host-attestation", "required", "exact-eligible-retained-report"),
    ("03", "evidence-replay", "required", "exact-wp7a-candidate"),
    ("04", "session-replay", "required", "exact-warmup-and-360-sample-correspondence"),
    ("05", "artifact-identity", "required", "exact-twelve-binaries-and-three-role-aggregates"),
    ("06", "toolchain-identity", "required", "exact-four-readable-receipts-and-role-aggregates"),
    ("07", "variance", "required", "all-twelve-cv-gates-pass"),
    ("08", "competitiveness", "required", "naux-over-specialized-not-greater-than-11-over-10"),
    ("09", "differentiation", "required", "generic-over-naux-not-less-than-5-over-4"),
    ("10", "intersection", "required", "at-least-one-same-kernel-passes-both"),
    ("11", "claim-boundary", "required", "candidate-never-self-admits-claim"),
)
CONTRACT_CLOSURES = (("01", "threshold-evaluator-unavailable", "closed", "wp7d-exact-replay"),)
CONTRACT_BLOCKERS = (
    ("01", "eligible-controlled-bundle-unavailable"),
    ("02", "tracked-public-protocol-acceptance-unavailable"),
    ("03", "performance-claim-authority-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP7D"),
    ("authority-id", "s4-bundle-threshold-evaluator-v1"),
    ("status", "threshold-evaluator-structurally-admitted"),
    ("claim-status", "not-admitted"),
    ("execution-policy", "forbidden"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-threshold-evaluator.yml",
    "distribution/s4-performance/WP7D-THRESHOLD.tsv",
    "distribution/s4-performance/WP7D-NONCLAIMS.md",
    "distribution/s4-performance/WP7D-README.md",
    "scripts/s4_threshold_evaluator.py",
    "scripts/tests/test_s4_threshold_evaluator_replay.py",
    "scripts/tests/test_s4_threshold_evaluator_static.py",
)
CORE_BUNDLE_FILES = (
    "HOST-ATTESTATION.tsv",
    "EVIDENCE.tsv",
    "SESSION.tsv",
    "TOOLCHAINS.tsv",
    "REPRODUCE.tsv",
)
ARTIFACT_FILES = tuple(
    f"artifacts/{role}-{name}/{kernel}-{kernel_name}"
    for role, name, _status in wp7a.ROLES
    for kernel, kernel_name, _oracle in wp7a.KERNELS
)
EXPECTED_BUNDLE_FILES = CORE_BUNDLE_FILES + ARTIFACT_FILES
EXPECTED_BUNDLE_DIRECTORIES = {
    "artifacts",
    *(f"artifacts/{role}-{name}" for role, name, _status in wp7a.ROLES),
}
EXPECTED_TOOLS = (
    ("01", "01", "cargo"),
    ("01", "02", "rustc"),
    ("02", "01", "cc"),
    ("03", "01", "cc"),
)


class ThresholdError(RuntimeError):
    """A fail-closed S4-WP7D evaluation error."""


@dataclass(frozen=True)
class Contract:
    seal: str


@dataclass(frozen=True)
class FileRecord:
    mode: int
    size: int
    sha256: str
    path: str


@dataclass(frozen=True)
class Authority:
    files: tuple[FileRecord, ...]
    seal: str


@dataclass(frozen=True)
class Admission:
    contract: Contract
    authority: Authority
    report: bytes
    report_root: str
    runner: wp7c.Admission
    evidence: wp7a.Admission


@dataclass(frozen=True)
class Manifest:
    root: str
    host_attestation: str
    source_commit: str
    files: tuple[tuple[str, int, str], ...]


@dataclass(frozen=True)
class BundleReplay:
    manifest: Manifest
    evidence: wp7a.Candidate
    report: bytes
    candidate_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(raw: bytes, label: str, maximum: int = 4_000_000) -> list[str]:
    if not raw or len(raw) > maximum or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise ThresholdError(f"{label} has invalid extent or encoding")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ThresholdError(f"{label} is not UTF-8") from error
    lines = text.splitlines()
    if any(not line for line in lines):
        raise ThresholdError(f"{label} contains a blank row")
    return lines


def _regular(path: Path, label: str, maximum: int = 4_000_000) -> bytes:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise ThresholdError(f"cannot read {label}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ThresholdError(f"{label} is not a regular file")
    if len(raw) > maximum:
        raise ThresholdError(f"{label} exceeds its extent limit")
    return raw


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    lines = _canonical(_regular(path, path.name), path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise ThresholdError(f"{path.name} magic or shape drifted")
    if any(line.startswith("seal\t") for line in lines[:-1]):
        raise ThresholdError(f"{path.name} has a non-terminal seal")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise ThresholdError(f"{path.name} seal row is malformed")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if _sha256(domain + body) != fields[1]:
        raise ThresholdError(f"{path.name} seal mismatch")
    return lines[1:-1], fields[1]


def _take(lines: list[str], index: int, tag: str, width: int) -> tuple[list[tuple[str, ...]], int]:
    rows: list[tuple[str, ...]] = []
    while index < len(lines) and lines[index].startswith(f"{tag}\t"):
        fields = lines[index].split("\t")
        if len(fields) != width:
            raise ThresholdError(f"WP7D {tag} row is malformed")
        rows.append(tuple(fields[1:]))
        index += 1
    return rows, index


def _safe_relative(value: str) -> None:
    if not PATH_RE.fullmatch(value):
        raise ThresholdError("path token is malformed")
    path = Path(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise ThresholdError("path is absolute or traversing")


def parse_contract(path: Path) -> Contract:
    lines, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    index = 0
    metadata, index = _take(lines, index, "meta", 3)
    gates, index = _take(lines, index, "gate", 5)
    closures, index = _take(lines, index, "closure", 5)
    blockers, index = _take(lines, index, "blocker", 3)
    if tuple(metadata) != CONTRACT_METADATA:
        raise ThresholdError("WP7D contract metadata drifted")
    if tuple(gates) != CONTRACT_GATES or tuple(closures) != CONTRACT_CLOSURES:
        raise ThresholdError("WP7D gate or closure set drifted")
    if tuple(blockers) != CONTRACT_BLOCKERS or index != len(lines):
        raise ThresholdError("WP7D blocker set or extent drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    index = 0
    metadata, index = _take(lines, index, "meta", 3)
    if tuple(metadata) != AUTHORITY_METADATA:
        raise ThresholdError("WP7D authority metadata drifted")
    expected_links = (
        ("component", "threshold-contract", "distribution/s4-performance/WP7D-THRESHOLD.tsv", contract_seal),
        ("parent", "benchmark-authority", "distribution/s4-performance/AUTHORITY.tsv", WP1_AUTHORITY_SEAL),
        ("parent", "evidence-law-authority", "distribution/s4-performance/WP7A-AUTHORITY.tsv", WP7A_AUTHORITY_SEAL),
        ("parent", "runner-authority", "distribution/s4-performance/WP7C-AUTHORITY.tsv", WP7C_AUTHORITY_SEAL),
    )
    links: list[tuple[str, ...]] = []
    for _expected in expected_links:
        if index >= len(lines):
            raise ThresholdError("WP7D authority binding is missing")
        links.append(tuple(lines[index].split("\t")))
        index += 1
    if tuple(links) != expected_links:
        raise ThresholdError("WP7D authority binding drifted")
    files: list[FileRecord] = []
    while index < len(lines):
        fields = lines[index].split("\t")
        if (
            len(fields) != 6
            or fields[0] != "file"
            or not MODE_RE.fullmatch(fields[1])
            or not UINT_RE.fullmatch(fields[2])
            or int(fields[2]) > 4_000_000
            or not HASH_RE.fullmatch(fields[3])
            or fields[5] != "threshold-evaluator"
        ):
            raise ThresholdError("WP7D authority file row is malformed")
        _safe_relative(fields[4])
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
        index += 1
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise ThresholdError("WP7D authority file inventory drifted")
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        raw = _regular(path, record.path)
        metadata = path.lstat()
        mode = stat.S_IFREG | stat.S_IMODE(metadata.st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise ThresholdError(f"WP7D bound file identity drifted: {record.path}")


def _verify_static_boundary(root: Path) -> None:
    workflow = (root / ".github/workflows/s4-threshold-evaluator.yml").read_text()
    if "--bundle" in workflow:
        raise ThresholdError("WP7D hosted workflow attempts bundle evaluation")
    for token in (
        "scripts/s4_threshold_evaluator.py",
        "test_s4_threshold_evaluator_static",
        "test_s4_threshold_evaluator_replay",
    ):
        if token not in workflow:
            raise ThresholdError("WP7D workflow omits a static gate")
    source = "\n".join((root / relative).read_text() for relative in EXPECTED_FILES)
    forbidden = (
        "import " + "time",
        "import " + "subprocess",
        "import " + "resource",
        "." + "clock_gettime(",
        "." + "monotonic(",
        "." + "perf_counter(",
        "Popen" + "(",
        "subprocess" + ".run(",
        "os." + "fork(",
        "os." + "execve(",
    )
    if any(token in source for token in forbidden):
        raise ThresholdError("WP7D source can read a clock or execute a workload")
    expected = {"WP7D-AUTHORITY.tsv", "WP7D-THRESHOLD.tsv", "WP7D-NONCLAIMS.md", "WP7D-README.md"}
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP7D-*")
        if path.is_file()
    }
    if actual != expected:
        raise ThresholdError("unexpected WP7D distribution artifact")


def _static_report(contract: Contract, authority: Authority) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"parent-benchmark-authority\t{WP1_AUTHORITY_SEAL}",
        f"parent-evidence-law\t{WP7A_AUTHORITY_SEAL}",
        f"parent-runner-authority\t{WP7C_AUTHORITY_SEAL}",
        "status\tthreshold-evaluator-structurally-admitted",
        "mode\tstatic-no-host-no-clock-no-execution",
        "claim-status\tnot-admitted",
        "blockers\t3",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve()
    benchmark = wp1.validate(root)
    if benchmark.authority.seal != WP1_AUTHORITY_SEAL:
        raise ThresholdError("accepted WP1 benchmark authority drifted")
    evidence = wp7a.validate(root)
    if evidence.authority.seal != WP7A_AUTHORITY_SEAL:
        raise ThresholdError("accepted WP7A evidence authority drifted")
    runner = wp7c.validate(root)
    if runner.authority.seal != WP7C_AUTHORITY_SEAL:
        raise ThresholdError("accepted WP7C runner authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP7D-THRESHOLD.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP7D-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_static_boundary(root)
    report, report_root = _static_report(contract, authority)
    return Admission(contract, authority, report, report_root, runner, evidence)


def _manifest(bundle: Path) -> Manifest:
    try:
        metadata = bundle.lstat()
    except OSError as error:
        raise ThresholdError("cannot inspect bundle directory") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ThresholdError("bundle is not a regular directory")
    manifest_path = bundle / "MANIFEST.tsv"
    raw = _regular(manifest_path, "bundle manifest", 1_000_000)
    if stat.S_IMODE(manifest_path.stat().st_mode) != 0o600:
        raise ThresholdError("bundle manifest mode drifted")
    lines = _canonical(raw, "bundle manifest", 1_000_000)
    if lines[0] != wp7c.BUNDLE_MAGIC or not lines[-1].startswith("bundle-root\t"):
        raise ThresholdError("bundle manifest magic or shape drifted")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise ThresholdError("bundle root row is malformed")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if _sha256(BUNDLE_DOMAIN + body) != fields[1]:
        raise ThresholdError("bundle root mismatch")
    index = 1
    metadata_rows, index = _take(lines[:-1], index, "meta", 3)
    metadata_map = dict(metadata_rows)
    expected_metadata = (
        ("runner-authority", WP7C_AUTHORITY_SEAL),
        ("host-attestation", metadata_map.get("host-attestation", "")),
        ("source-commit", metadata_map.get("source-commit", "")),
        ("claim-status", "not-admitted"),
        ("file-count", str(len(EXPECTED_BUNDLE_FILES))),
    )
    if (
        tuple(metadata_rows) != expected_metadata
        or not HASH_RE.fullmatch(metadata_map.get("host-attestation", ""))
        or not COMMIT_RE.fullmatch(metadata_map.get("source-commit", ""))
    ):
        raise ThresholdError("bundle metadata drifted")
    file_rows, index = _take(lines[:-1], index, "file", 4)
    if index != len(lines) - 1 or len(file_rows) != len(EXPECTED_BUNDLE_FILES):
        raise ThresholdError("bundle manifest file extent drifted")
    records: list[tuple[str, int, str]] = []
    for row, expected_path in zip(file_rows, EXPECTED_BUNDLE_FILES, strict=True):
        path, size, digest = row
        if path != expected_path or not UINT_RE.fullmatch(size) or not HASH_RE.fullmatch(digest):
            raise ThresholdError("bundle file order or identity row drifted")
        _safe_relative(path)
        records.append((path, int(size), digest))
    return Manifest(
        fields[1], metadata_map["host-attestation"], metadata_map["source-commit"], tuple(records)
    )


def _verify_inventory(bundle: Path, manifest: Manifest) -> None:
    expected_files = {"MANIFEST.tsv", *(path for path, _size, _digest in manifest.files)}
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for path in bundle.rglob("*"):
        relative = path.relative_to(bundle).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ThresholdError("bundle contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            actual_directories.add(relative)
        elif stat.S_ISREG(metadata.st_mode):
            actual_files.add(relative)
        else:
            raise ThresholdError("bundle contains a non-regular entry")
    if actual_files != expected_files or actual_directories != EXPECTED_BUNDLE_DIRECTORIES:
        raise ThresholdError("bundle contains missing or extra entries")
    records = dict((path, (size, digest)) for path, size, digest in manifest.files)
    for relative in EXPECTED_BUNDLE_FILES:
        path = bundle / relative
        raw = _regular(path, relative)
        expected_mode = 0o700 if relative.startswith("artifacts/") else 0o600
        size, digest = records[relative]
        if stat.S_IMODE(path.stat().st_mode) != expected_mode or len(raw) != size or _sha256(raw) != digest:
            raise ThresholdError(f"bundle file identity or mode drifted: {relative}")


def _evidence_role_rows(raw: bytes) -> dict[str, tuple[str, str, str, str]]:
    lines = _canonical(raw, "bundle evidence", 2_000_000)
    rows = [line.split("\t") for line in lines if line.startswith("role\t")]
    if len(rows) != 3:
        raise ThresholdError("evidence role rows drifted")
    result: dict[str, tuple[str, str, str, str]] = {}
    for fields, expected in zip(rows, wp7a.ROLES, strict=True):
        if len(fields) != 6 or tuple(fields[1:3]) != expected[:2] or fields[5] != expected[2]:
            raise ThresholdError("evidence role identity drifted")
        if not HASH_RE.fullmatch(fields[3]) or not HASH_RE.fullmatch(fields[4]):
            raise ThresholdError("evidence role aggregate is malformed")
        result[fields[1]] = (fields[2], fields[3], fields[4], fields[5])
    return result


def _aggregate_binary(bundle: Path, role: str, role_name: str) -> str:
    body = b""
    for kernel, kernel_name, _oracle in wp7a.KERNELS:
        path = bundle / f"artifacts/{role}-{role_name}/{kernel}-{kernel_name}"
        raw = _regular(path, f"{role}/{kernel} artifact")
        if not os.access(path, os.X_OK):
            raise ThresholdError("retained artifact is non-executable")
        body += f"artifact\t{kernel}\t{_sha256(raw)}\t{len(raw)}\n".encode()
    return _sha256(BINARY_DOMAIN + body)


def _toolchains(bundle: Path, manifest: Manifest) -> dict[str, str]:
    lines = _canonical(_regular(bundle / "TOOLCHAINS.tsv", "toolchain receipt"), "toolchain receipt")
    if lines[0] != wp7c.TOOLCHAIN_MAGIC or not lines[-1].startswith("toolchain-root\t"):
        raise ThresholdError("toolchain receipt magic or shape drifted")
    root_fields = lines[-1].split("\t")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if (
        len(root_fields) != 2
        or not HASH_RE.fullmatch(root_fields[1])
        or _sha256(TOOLCHAIN_RECEIPT_DOMAIN + body) != root_fields[1]
    ):
        raise ThresholdError("toolchain receipt root mismatch")
    expected_metadata = (
        ("runner-authority", WP7C_AUTHORITY_SEAL),
        ("source-commit", manifest.source_commit),
        ("claim-status", "not-admitted"),
    )
    index = 1
    metadata, index = _take(lines[:-1], index, "meta", 3)
    if tuple(metadata) != expected_metadata:
        raise ThresholdError("toolchain receipt metadata drifted")
    tool_rows, index = _take(lines[:-1], index, "tool", 8)
    if index != len(lines) - 1 or len(tool_rows) != len(EXPECTED_TOOLS):
        raise ThresholdError("toolchain receipt extent drifted")
    by_role: dict[str, list[tuple[str, str, str]]] = {role: [] for role, _name, _status in wp7a.ROLES}
    for row, expected in zip(tool_rows, EXPECTED_TOOLS, strict=True):
        role, ordinal, name, path, executable_hash, version_hash, version_hex = row
        if (role, ordinal, name) != expected or not path or any(character in path for character in "\0\r\n\t"):
            raise ThresholdError("toolchain receipt identity drifted")
        if not HASH_RE.fullmatch(executable_hash) or not HASH_RE.fullmatch(version_hash):
            raise ThresholdError("toolchain receipt hash is malformed")
        try:
            version = bytes.fromhex(version_hex)
        except ValueError as error:
            raise ThresholdError("toolchain version is not canonical hex") from error
        if not version or version.hex() != version_hex or _sha256(version) != version_hash:
            raise ThresholdError("toolchain version bytes differ from their hash")
        by_role[role].append((name, executable_hash, version_hash))
    aggregates: dict[str, str] = {}
    for role, rows in by_role.items():
        aggregate_body = b"".join(
            f"tool\t{name}\t{executable_hash}\t{version_hash}\n".encode()
            for name, executable_hash, version_hash in rows
        )
        aggregates[role] = _sha256(TOOLCHAIN_DOMAIN + aggregate_body)
    return aggregates


def _evidence_observations(raw: bytes) -> tuple[
    dict[tuple[str, str], tuple[int, int, str]],
    dict[tuple[str, str, int], tuple[int, int, str]],
]:
    lines = _canonical(raw, "bundle evidence", 2_000_000)
    warmups: dict[tuple[str, str], tuple[int, int, str]] = {}
    samples: dict[tuple[str, str, int], tuple[int, int, str]] = {}
    for line in lines:
        if line.startswith("warmup\t"):
            fields = line.split("\t")
            if len(fields) != 6:
                raise ThresholdError("evidence warmup row is malformed")
            warmups[(fields[1], fields[2])] = (int(fields[3]), int(fields[4]), fields[5])
        elif line.startswith("sample\t"):
            fields = line.split("\t")
            if len(fields) != 7:
                raise ThresholdError("evidence sample row is malformed")
            samples[(fields[1], fields[2], int(fields[3]))] = (
                int(fields[4]), int(fields[5]), fields[6]
            )
    if len(warmups) != 12 or len(samples) != 360:
        raise ThresholdError("evidence observation extent drifted")
    return warmups, samples


def _session(bundle: Path, manifest: Manifest, evidence_raw: bytes, evidence_root: str) -> None:
    lines = _canonical(_regular(bundle / "SESSION.tsv", "measurement session", 4_000_000), "measurement session")
    if lines[0] != wp7c.SESSION_MAGIC or not lines[-1].startswith("session-root\t"):
        raise ThresholdError("measurement session magic or shape drifted")
    root_fields = lines[-1].split("\t")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if (
        len(root_fields) != 2
        or not HASH_RE.fullmatch(root_fields[1])
        or _sha256(SESSION_DOMAIN + body) != root_fields[1]
    ):
        raise ThresholdError("measurement session root mismatch")
    expected_metadata = (
        ("runner-authority", WP7C_AUTHORITY_SEAL),
        ("host-attestation", manifest.host_attestation),
        ("source-commit", manifest.source_commit),
        ("evidence-root", evidence_root),
        ("claim-status", "not-admitted"),
    )
    index = 1
    metadata, index = _take(lines[:-1], index, "meta", 3)
    if tuple(metadata) != expected_metadata:
        raise ThresholdError("measurement session metadata drifted")
    evidence_warmups, evidence_samples = _evidence_observations(evidence_raw)
    pairs = tuple(
        (role, kernel, oracle, status)
        for role, _role_name, status in wp7a.ROLES
        for kernel, _kernel_name, oracle in wp7a.KERNELS
    )
    for role, kernel, oracle, status in pairs:
        count = 0
        cumulative = 0
        while index < len(lines) - 1 and lines[index].startswith(f"warmup-run\t{role}\t{kernel}\t"):
            fields = lines[index].split("\t")
            count += 1
            if (
                len(fields) != 9
                or fields[3] != f"{count:06}"
                or not all(POSITIVE_RE.fullmatch(value) for value in fields[4:7])
                or not INT_RE.fullmatch(fields[7])
                or int(fields[7]) != oracle
                or fields[8] != status
                or int(fields[5]) <= int(fields[4])
            ):
                raise ThresholdError("measurement warmup invocation drifted")
            cumulative += int(fields[4])
            index += 1
        if count == 0 or count > wp7c.MAX_WARMUP_INVOCATIONS or cumulative < wp7c.WARMUP_MINIMUM_NS:
            raise ThresholdError("measurement warmup completeness drifted")
        if evidence_warmups[(role, kernel)] != (cumulative, oracle, status):
            raise ThresholdError("session warmup differs from evidence")
    for role, kernel, oracle, status in pairs:
        for ordinal in range(1, wp7c.SAMPLE_COUNT + 1):
            if index >= len(lines) - 1:
                raise ThresholdError("measurement sample set is truncated")
            fields = lines[index].split("\t")
            if (
                len(fields) != 9
                or tuple(fields[1:4]) != (role, kernel, f"{ordinal:02}")
                or not all(POSITIVE_RE.fullmatch(value) for value in fields[4:7])
                or not INT_RE.fullmatch(fields[7])
                or int(fields[7]) != oracle
                or fields[8] != status
                or int(fields[5]) <= int(fields[4])
            ):
                raise ThresholdError("measurement sample invocation drifted")
            observed = (int(fields[4]), int(fields[7]), fields[8])
            if evidence_samples[(role, kernel, ordinal)] != observed:
                raise ThresholdError("session sample differs from evidence")
            index += 1
    if index != len(lines) - 1:
        raise ThresholdError("measurement session has trailing rows")


def _reproduction(bundle: Path, manifest: Manifest) -> None:
    lines = _canonical(_regular(bundle / "REPRODUCE.tsv", "reproduction receipt"), "reproduction receipt")
    if len(lines) != 6 or lines[0] != "NAUX-S4-MEASUREMENT-REPRODUCTION\t1":
        raise ThresholdError("reproduction receipt shape drifted")
    expected = (
        ("source-commit", manifest.source_commit),
        ("runner-authority", WP7C_AUTHORITY_SEAL),
        ("host-attestation-root", manifest.host_attestation),
    )
    for line, row in zip(lines[1:4], expected, strict=True):
        if tuple(line.split("\t")) != row:
            raise ThresholdError("reproduction authority drifted")
    origin = lines[4].split("\t")
    if len(origin) != 2 or origin[0] != "original-host-attestation" or not origin[1]:
        raise ThresholdError("reproduction origin is malformed")
    if lines[5] != "policy\tnew-eligible-attestation-and-new-output-required-for-each-run":
        raise ThresholdError("reproduction policy drifted")


def _threshold_report(
    admission: Admission,
    manifest: Manifest,
    evidence: wp7a.Candidate,
) -> tuple[bytes, str]:
    statistics = {(stat.role, stat.kernel): stat for stat in evidence.statistics}
    rows = [
        CANDIDATE_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"runner-authority\t{WP7C_AUTHORITY_SEAL}",
        f"bundle-root\t{manifest.root}",
        f"evidence-root\t{evidence.evidence_root}",
        f"host-attestation\t{manifest.host_attestation}",
        f"source-commit\t{manifest.source_commit}",
        f"variance-gate\t{'pass' if evidence.variance_gate else 'fail'}",
    ]
    competitive_count = 0
    differentiated_count = 0
    intersection_count = 0
    for kernel, name, _oracle in wp7a.KERNELS:
        naux = statistics[("01", kernel)]
        generic = statistics[("02", kernel)]
        specialized = statistics[("03", kernel)]
        competitive = (
            10 * naux.median_num * specialized.median_den
            <= 11 * specialized.median_num * naux.median_den
        )
        differentiated = (
            4 * generic.median_num * naux.median_den
            >= 5 * naux.median_num * generic.median_den
        )
        intersection = competitive and differentiated
        competitive_count += int(competitive)
        differentiated_count += int(differentiated)
        intersection_count += int(intersection)
        rows.append(
            f"kernel\t{kernel}\t{name}\t"
            f"{naux.median_num}\t{naux.median_den}\t"
            f"{generic.median_num}\t{generic.median_den}\t"
            f"{specialized.median_num}\t{specialized.median_den}\t"
            f"{'pass' if competitive else 'fail'}\t"
            f"{'pass' if differentiated else 'fail'}\t"
            f"{'pass' if intersection else 'fail'}"
        )
    threshold_pass = evidence.variance_gate and intersection_count > 0
    rows.extend(
        (
            f"competitive-kernels\t{competitive_count}",
            f"differentiated-kernels\t{differentiated_count}",
            f"intersection-kernels\t{intersection_count}",
            f"threshold-candidate\t{'pass' if threshold_pass else 'fail'}",
            "claim-status\tnot-admitted",
            "claim-authority\trequired-not-admitted",
        )
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(CANDIDATE_DOMAIN + body)
    return body + f"candidate-root\t{root}\n".encode(), root


def replay_bundle(bundle: Path, admission: Admission) -> BundleReplay:
    bundle = bundle.expanduser().absolute()
    manifest = _manifest(bundle)
    bundle = bundle.resolve(strict=True)
    _verify_inventory(bundle, manifest)
    retained = wp7c.parse_retained_host(bundle / "HOST-ATTESTATION.tsv", admission.runner)
    if retained.report_root != manifest.host_attestation or retained.commit != manifest.source_commit:
        raise ThresholdError("retained host report differs from bundle manifest")
    evidence_raw = _regular(bundle / "EVIDENCE.tsv", "bundle evidence", 2_000_000)
    carrier_authority = _sha256((WP7B_NAUX_AUTHORITY_SEAL + WP7B_C_AUTHORITY_SEAL).encode())
    evidence = wp7a.replay_candidate(
        evidence_raw,
        admission.evidence,
        carrier_authority=carrier_authority,
        host_attestation=manifest.host_attestation,
        runner_authority=WP7C_AUTHORITY_SEAL,
    )
    role_rows = _evidence_role_rows(evidence_raw)
    for role, role_name, _status in wp7a.ROLES:
        if _aggregate_binary(bundle, role, role_name) != role_rows[role][1]:
            raise ThresholdError("retained artifact aggregate differs from evidence")
    toolchain_aggregates = _toolchains(bundle, manifest)
    for role, _role_name, _status in wp7a.ROLES:
        if toolchain_aggregates[role] != role_rows[role][2]:
            raise ThresholdError("retained toolchain aggregate differs from evidence")
    _session(bundle, manifest, evidence_raw, evidence.evidence_root)
    _reproduction(bundle, manifest)
    report, root = _threshold_report(admission, manifest, evidence)
    return BundleReplay(manifest, evidence, report, root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--bundle", type=Path)
    arguments = parser.parse_args(argv)
    try:
        admission = validate(arguments.root)
        if arguments.bundle is None:
            sys.stdout.buffer.write(admission.report)
        else:
            sys.stdout.buffer.write(replay_bundle(arguments.bundle, admission).report)
        return 0
    except (
        ThresholdError,
        wp1.BenchmarkAuthorityError,
        wp7a.EvidenceError,
        wp7c.RunnerError,
        wp7a.wp6.HostControlError,
        OSError,
        ValueError,
    ) as error:
        print(f"S4-WP7D validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
