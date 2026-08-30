#!/usr/bin/env python3
"""Validate or replay S4-WP8L register-residency candidate evidence."""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_measurement_runner as wp8k


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-EVIDENCE-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-EVIDENCE-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-EVIDENCE-REPORT\t1"
EVIDENCE_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-EVIDENCE\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-evidence:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-evidence:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-evidence:report:v1\0"
EVIDENCE_DOMAIN = b"NAUX:s4-register-residency-evidence:result:v1\0"
CONTRACT_SEAL = "2050c6c79685568b5481189d483f561ef45c8b318c892fa15b7dd5ce1ae941e6"
WP8K_AUTHORITY_SEAL = "3c7f1ce549764dd5a2d3bc28dfeec3c091aaae835f44490ac6a3418e0f852fc2"
WP8J_AUTHORITY_SEAL = "aaa90c3a2674f7c13208bbb895b8365c01bd5cc9b60c86ff26fa29727d9c11f1"
BUNDLE_DOMAIN = b"NAUX:s4-register-residency-raw-bundle:v1\0"
SESSION_DOMAIN = b"NAUX:s4-register-residency-raw-session:v1\0"
TOOLCHAIN_RECEIPT_DOMAIN = b"NAUX:s4-register-residency-toolchains:v1\0"
BINARY_DOMAIN = b"NAUX:s4-measurement-runner:role-binary:v1\0"
TOOLCHAIN_DOMAIN = b"NAUX:s4-measurement-runner:toolchain:v1\0"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
POSITIVE_RE = re.compile(r"[1-9][0-9]*\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MAX_TEXT_BYTES = 4_000_000
MAX_ARTIFACT_BYTES = 1_000_000

METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-candidate-runner-authority", WP8K_AUTHORITY_SEAL),
    ("parent-candidate-carrier-authority", WP8J_AUTHORITY_SEAL),
    ("status", "candidate-evidence-replay-structurally-admitted"),
    ("input", "exact-wp8k-raw-bundle-v1"),
    ("default-mode", "static-no-bundle-no-host-no-clock-no-execution"),
    ("replay-mode", "explicit-read-only"),
    ("inventory-policy", "exact-eight-payload-files-and-manifest"),
    ("sample-policy", "four-kernels-exact30-no-drop-no-retry"),
    ("statistics-policy", "exact-integer-min-max-total-median"),
    ("artifact-policy", "exact-four-wp8j-timing-images"),
    ("claim-status", "not-admitted"),
    ("target", "x86_64-unknown-linux-gnu"),
)
GATES = (
    ("01", "static-isolation", "required", "no-bundle-no-host-no-clock-no-execution"),
    ("02", "bundle-root", "required", "exact-wp8k-manifest-and-inventory"),
    ("03", "host-attestation", "required", "exact-eligible-retained-wp8i-report"),
    ("04", "session-root", "required", "exact-warmups-and-120-samples"),
    ("05", "artifact-identity", "required", "exact-four-wp8j-images-and-role-aggregate"),
    ("06", "toolchain-identity", "required", "exact-portable-receipts-and-role-aggregate"),
    ("07", "result-parity", "required", "every-checksum-matches-frozen-oracle"),
    ("08", "reproduction", "required", "exact-source-host-runner-binding"),
    ("09", "statistics", "required", "exact-clock-free-reduction-only"),
    ("10", "claim-boundary", "required", "replay-never-self-admits-claim"),
)
CLOSURES = (
    ("01", "candidate-raw-bundle-verifier-unavailable", "closed", "wp8l-independent-replay"),
)
BLOCKERS = (
    ("01", "eligible-candidate-raw-bundle-unavailable"),
    ("02", "baseline-candidate-comparison-unavailable"),
    ("03", "performance-claim-authority-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8L"),
    ("authority-id", "s4-register-residency-evidence-v1"),
    ("status", "candidate-evidence-replay-structurally-admitted"),
    ("claim-status", "not-admitted"),
    ("execution-policy", "forbidden"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-evidence.yml",
    "distribution/s4-performance/WP8L-EVIDENCE.tsv",
    "distribution/s4-performance/WP8L-NONCLAIMS.md",
    "distribution/s4-performance/WP8L-README.md",
    "scripts/s4_register_residency_evidence.py",
    "scripts/tests/test_s4_register_residency_evidence_replay.py",
    "scripts/tests/test_s4_register_residency_evidence_static.py",
)
CORE_BUNDLE_FILES = (
    "HOST-ATTESTATION.tsv",
    "RAW-SESSION.tsv",
    "TOOLCHAINS.tsv",
    "REPRODUCE.tsv",
)
ARTIFACT_FILES = tuple(
    f"artifacts/{ordinal}-{name}" for ordinal, name, _oracle in wp8k.KERNELS
)
EXPECTED_BUNDLE_FILES = CORE_BUNDLE_FILES + ARTIFACT_FILES


class CandidateEvidenceError(RuntimeError):
    """A fail-closed WP8L validation or replay error."""


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
    runner: wp8k.Admission
    static_report: bytes
    report_root: str


@dataclass(frozen=True)
class Manifest:
    root: str
    host_attestation: str
    session_root: str
    source_commit: str
    files: tuple[tuple[str, int, str], ...]


@dataclass(frozen=True)
class KernelStatistic:
    ordinal: str
    name: str
    oracle: int
    warmup_count: int
    warmup_ns: int
    sample_count: int
    minimum_ns: int
    maximum_ns: int
    total_ns: int
    median_num: int
    median_den: int


@dataclass(frozen=True)
class Session:
    root: str
    binary_hash: str
    toolchain_hash: str
    statistics: tuple[KernelStatistic, ...]


@dataclass(frozen=True)
class Replay:
    manifest: Manifest
    session: Session
    evidence: bytes
    evidence_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_regular(path: Path, label: str, maximum: int = MAX_TEXT_BYTES) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise CandidateEvidenceError(f"cannot inspect {label}") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size > maximum
    ):
        raise CandidateEvidenceError(f"{label} is not a bounded regular file")
    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            raw = handle.read(maximum + 1)
            after = os.fstat(handle.fileno())
        rebound = path.lstat()
    except OSError as error:
        raise CandidateEvidenceError(f"cannot read {label}") from error
    if (
        (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        or (opened.st_dev, opened.st_ino, opened.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or len(raw) != after.st_size
        or stat.S_ISLNK(rebound.st_mode)
        or (rebound.st_dev, rebound.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise CandidateEvidenceError(f"{label} changed while read")
    return raw


def _canonical(raw: bytes, label: str, maximum: int = MAX_TEXT_BYTES) -> list[str]:
    if (
        not raw
        or len(raw) > maximum
        or not raw.endswith(b"\n")
        or b"\r" in raw
        or b"\0" in raw
    ):
        raise CandidateEvidenceError(f"{label} has invalid canonical extent")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise CandidateEvidenceError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise CandidateEvidenceError(f"{label} contains blank or padded rows")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    raw = _read_regular(path, path.name)
    lines = _canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise CandidateEvidenceError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if (
        len(fields) != 2
        or not HASH_RE.fullmatch(fields[1])
        or _sha256(domain + body) != fields[1]
    ):
        raise CandidateEvidenceError(f"{path.name} seal drifted")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL:
        raise CandidateEvidenceError("WP8L contract identity drifted")
    expected = [f"meta\t{key}\t{value}" for key, value in METADATA]
    expected.extend(
        f"gate\t{ordinal}\t{name}\t{status}\t{detail}"
        for ordinal, name, status, detail in GATES
    )
    expected.extend(
        f"closure\t{ordinal}\t{name}\t{status}\t{detail}"
        for ordinal, name, status, detail in CLOSURES
    )
    expected.extend(f"blocker\t{ordinal}\t{name}" for ordinal, name in BLOCKERS)
    if rows != expected:
        raise CandidateEvidenceError("WP8L contract rows drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    prefix = [f"meta\t{key}\t{value}" for key, value in AUTHORITY_METADATA]
    prefix.extend(
        (
            "component\tcandidate-evidence-contract\t"
            f"distribution/s4-performance/WP8L-EVIDENCE.tsv\t{contract_seal}",
            "parent\tcandidate-runner-authority\t"
            f"distribution/s4-performance/WP8K-AUTHORITY.tsv\t{WP8K_AUTHORITY_SEAL}",
            "parent\tcandidate-carrier-authority\t"
            f"distribution/s4-performance/WP8J-AUTHORITY.tsv\t{WP8J_AUTHORITY_SEAL}",
        )
    )
    if rows[: len(prefix)] != prefix:
        raise CandidateEvidenceError("WP8L authority metadata or parent binding drifted")
    records = []
    for row in rows[len(prefix) :]:
        fields = row.split("\t")
        if (
            len(fields) != 6
            or fields[0] != "file"
            or not MODE_RE.fullmatch(fields[1])
            or not UINT_RE.fullmatch(fields[2])
            or not HASH_RE.fullmatch(fields[3])
            or fields[4] not in EXPECTED_FILES
            or fields[5] != "candidate-evidence-replay"
        ):
            raise CandidateEvidenceError("WP8L authority file row is malformed")
        records.append(
            FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4])
        )
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise CandidateEvidenceError("WP8L authority inventory drifted")
    return Authority(tuple(records), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        raw = _read_regular(path, record.path)
        mode = stat.S_IFREG | stat.S_IMODE(path.lstat().st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise CandidateEvidenceError(f"bound WP8L file drifted: {record.path}")


def _static_report(contract: Contract, authority: Authority) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"candidate-runner-authority\t{WP8K_AUTHORITY_SEAL}",
        f"candidate-carrier-authority\t{WP8J_AUTHORITY_SEAL}",
        "status\tcandidate-evidence-replay-structurally-admitted",
        "mode\tstatic-no-bundle-no-host-no-clock-no-execution",
        "bundle-status\texternal-eligible-bundle-required",
        "claim-status\tnot-admitted",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    runner = wp8k.validate(root)
    if runner.authority.seal != WP8K_AUTHORITY_SEAL:
        raise CandidateEvidenceError("WP8K parent authority drifted")
    if runner.carrier.authority.seal != WP8J_AUTHORITY_SEAL:
        raise CandidateEvidenceError("WP8J parent authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP8L-EVIDENCE.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP8L-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    report, report_root = _static_report(contract, authority)
    return Admission(contract, authority, runner, report, report_root)


def _bundle_directory(path: Path) -> Path:
    absolute = path.expanduser().absolute()
    try:
        metadata = absolute.lstat()
    except OSError as error:
        raise CandidateEvidenceError("cannot inspect candidate bundle") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise CandidateEvidenceError("candidate bundle is not a real directory")
    return absolute.resolve(strict=True)


def _safe_relative(value: str) -> None:
    if not PATH_RE.fullmatch(value):
        raise CandidateEvidenceError("bundle path token is malformed")
    path = Path(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise CandidateEvidenceError("bundle path is absolute or traversing")


def parse_manifest(bundle: Path) -> Manifest:
    raw = _read_regular(bundle / "MANIFEST.tsv", "candidate bundle manifest")
    lines = _canonical(raw, "candidate bundle manifest")
    if lines[0] != wp8k.BUNDLE_MAGIC or not lines[-1].startswith("bundle-root\t"):
        raise CandidateEvidenceError("candidate manifest magic or shape drifted")
    body = raw[: -(len(lines[-1]) + 1)]
    root_fields = lines[-1].split("\t")
    if (
        len(root_fields) != 2
        or not HASH_RE.fullmatch(root_fields[1])
        or _sha256(BUNDLE_DOMAIN + body) != root_fields[1]
    ):
        raise CandidateEvidenceError("candidate manifest root mismatch")
    metadata = []
    index = 1
    while index < len(lines) - 1 and lines[index].startswith("meta\t"):
        fields = lines[index].split("\t")
        if len(fields) != 3:
            raise CandidateEvidenceError("candidate manifest metadata is malformed")
        metadata.append((fields[1], fields[2]))
        index += 1
    if len(metadata) != 6:
        raise CandidateEvidenceError("candidate manifest metadata extent drifted")
    values = dict(metadata)
    expected_keys = (
        "runner-authority",
        "host-attestation",
        "session-root",
        "source-commit",
        "claim-status",
        "file-count",
    )
    if tuple(key for key, _value in metadata) != expected_keys:
        raise CandidateEvidenceError("candidate manifest metadata order drifted")
    if (
        values["runner-authority"] != WP8K_AUTHORITY_SEAL
        or not HASH_RE.fullmatch(values["host-attestation"])
        or not HASH_RE.fullmatch(values["session-root"])
        or not COMMIT_RE.fullmatch(values["source-commit"])
        or values["claim-status"] != "not-admitted"
        or values["file-count"] != str(len(EXPECTED_BUNDLE_FILES))
    ):
        raise CandidateEvidenceError("candidate manifest authority or identity drifted")
    files = []
    while index < len(lines) - 1:
        fields = lines[index].split("\t")
        if (
            len(fields) != 4
            or fields[0] != "file"
            or not POSITIVE_RE.fullmatch(fields[2])
            or not HASH_RE.fullmatch(fields[3])
        ):
            raise CandidateEvidenceError("candidate manifest file row is malformed")
        _safe_relative(fields[1])
        files.append((fields[1], int(fields[2]), fields[3]))
        index += 1
    if tuple(path for path, _size, _digest in files) != EXPECTED_BUNDLE_FILES:
        raise CandidateEvidenceError("candidate manifest file inventory drifted")
    return Manifest(
        root_fields[1],
        values["host-attestation"],
        values["session-root"],
        values["source-commit"],
        tuple(files),
    )


def verify_inventory(bundle: Path, manifest: Manifest) -> None:
    expected_root = {"MANIFEST.tsv", *CORE_BUNDLE_FILES, "artifacts"}
    try:
        root_entries = {entry.name for entry in bundle.iterdir()}
    except OSError as error:
        raise CandidateEvidenceError("cannot enumerate candidate bundle") from error
    if root_entries != expected_root:
        raise CandidateEvidenceError("candidate bundle root inventory drifted")
    artifacts = bundle / "artifacts"
    try:
        artifact_metadata = artifacts.lstat()
        artifact_entries = {entry.name for entry in artifacts.iterdir()}
    except OSError as error:
        raise CandidateEvidenceError("cannot enumerate candidate artifacts") from error
    if stat.S_ISLNK(artifact_metadata.st_mode) or not stat.S_ISDIR(artifact_metadata.st_mode):
        raise CandidateEvidenceError("candidate artifacts path is not a real directory")
    if artifact_entries != {Path(path).name for path in ARTIFACT_FILES}:
        raise CandidateEvidenceError("candidate artifact inventory drifted")
    records = {path: (size, digest) for path, size, digest in manifest.files}
    for relative in EXPECTED_BUNDLE_FILES:
        maximum = MAX_ARTIFACT_BYTES if relative.startswith("artifacts/") else MAX_TEXT_BYTES
        raw = _read_regular(bundle / relative, relative, maximum)
        size, digest = records[relative]
        expected_mode = 0o700 if relative.startswith("artifacts/") else 0o600
        if (
            len(raw) != size
            or _sha256(raw) != digest
            or stat.S_IMODE((bundle / relative).lstat().st_mode) != expected_mode
        ):
            raise CandidateEvidenceError(f"candidate bundle file drifted: {relative}")
    if stat.S_IMODE((bundle / "MANIFEST.tsv").lstat().st_mode) != 0o600:
        raise CandidateEvidenceError("candidate manifest mode drifted")


def artifact_identity(bundle: Path, admission: Admission) -> tuple[str, int]:
    records = admission.runner.carrier.contract.records
    if len(records) != len(wp8k.KERNELS):
        raise CandidateEvidenceError("WP8J artifact record extent drifted")
    rows = []
    total = 0
    for record, (ordinal, name, oracle) in zip(records, wp8k.KERNELS, strict=True):
        path = bundle / f"artifacts/{ordinal}-{name}"
        raw = _read_regular(path, f"candidate artifact {ordinal}", MAX_ARTIFACT_BYTES)
        if (
            record.ordinal != int(ordinal)
            or record.name != name
            or record.oracle != oracle
            or len(raw) != record.elf_bytes
            or _sha256(raw) != record.elf_hash
        ):
            raise CandidateEvidenceError(f"candidate artifact {ordinal} differs from WP8J")
        rows.append(f"artifact\t{ordinal}\t{record.elf_hash}\t{record.elf_bytes}\n")
        total += len(raw)
    body = "".join(rows).encode()
    return _sha256(BINARY_DOMAIN + body), total


def toolchain_identity(bundle: Path, manifest: Manifest) -> str:
    raw = _read_regular(bundle / "TOOLCHAINS.tsv", "candidate toolchain receipt")
    lines = _canonical(raw, "candidate toolchain receipt")
    if lines[0] != wp8k.TOOLCHAIN_MAGIC or not lines[-1].startswith("toolchain-root\t"):
        raise CandidateEvidenceError("candidate toolchain receipt shape drifted")
    body = raw[: -(len(lines[-1]) + 1)]
    root_fields = lines[-1].split("\t")
    if (
        len(root_fields) != 2
        or not HASH_RE.fullmatch(root_fields[1])
        or _sha256(TOOLCHAIN_RECEIPT_DOMAIN + body) != root_fields[1]
    ):
        raise CandidateEvidenceError("candidate toolchain receipt root mismatch")
    expected_metadata = (
        f"meta\trunner-authority\t{WP8K_AUTHORITY_SEAL}",
        f"meta\tsource-commit\t{manifest.source_commit}",
        "meta\tclaim-status\tnot-admitted",
    )
    if tuple(lines[1:4]) != expected_metadata:
        raise CandidateEvidenceError("candidate toolchain metadata drifted")
    expected_tools = (("01", "cargo"), ("02", "rustc"))
    aggregate = []
    if len(lines[4:-1]) != len(expected_tools):
        raise CandidateEvidenceError("candidate toolchain extent drifted")
    for line, (ordinal, name) in zip(lines[4:-1], expected_tools, strict=True):
        fields = line.split("\t")
        if (
            len(fields) != 7
            or tuple(fields[1:3]) != (ordinal, name)
            or not fields[3]
            or any(character in fields[3] for character in "\0\r\n\t")
            or not HASH_RE.fullmatch(fields[4])
            or not HASH_RE.fullmatch(fields[5])
        ):
            raise CandidateEvidenceError("candidate toolchain row is malformed")
        try:
            version = bytes.fromhex(fields[6])
        except ValueError as error:
            raise CandidateEvidenceError("candidate toolchain version is not hex") from error
        if not version or version.hex() != fields[6] or _sha256(version) != fields[5]:
            raise CandidateEvidenceError("candidate toolchain version identity drifted")
        aggregate.append(f"tool\t{name}\t{fields[4]}\t{fields[5]}\n")
    return _sha256(TOOLCHAIN_DOMAIN + "".join(aggregate).encode())


def _positive(value: str, label: str) -> int:
    if not POSITIVE_RE.fullmatch(value):
        raise CandidateEvidenceError(f"{label} is not a positive integer")
    return int(value)


def _checksum(value: str, oracle: int) -> int:
    if not INT_RE.fullmatch(value) or int(value) != oracle:
        raise CandidateEvidenceError("candidate checksum differs from its frozen oracle")
    return int(value)


def _median(values: list[int]) -> tuple[int, int]:
    ordered = sorted(values)
    numerator = ordered[len(ordered) // 2 - 1] + ordered[len(ordered) // 2]
    denominator = 2
    divisor = math.gcd(numerator, denominator)
    return numerator // divisor, denominator // divisor


def parse_session(
    bundle: Path,
    manifest: Manifest,
    binary_hash: str,
    code_size: int,
    toolchain_hash: str,
) -> Session:
    raw = _read_regular(bundle / "RAW-SESSION.tsv", "candidate raw session")
    lines = _canonical(raw, "candidate raw session")
    if lines[0] != wp8k.SESSION_MAGIC or not lines[-1].startswith("session-root\t"):
        raise CandidateEvidenceError("candidate session shape drifted")
    body = raw[: -(len(lines[-1]) + 1)]
    root_fields = lines[-1].split("\t")
    if (
        len(root_fields) != 2
        or not HASH_RE.fullmatch(root_fields[1])
        or _sha256(SESSION_DOMAIN + body) != root_fields[1]
        or root_fields[1] != manifest.session_root
    ):
        raise CandidateEvidenceError("candidate session root mismatch")
    expected_metadata = (
        f"meta\trunner-authority\t{WP8K_AUTHORITY_SEAL}",
        f"meta\thost-attestation\t{manifest.host_attestation}",
        f"meta\tsource-commit\t{manifest.source_commit}",
        f"meta\tcarrier-authority\t{WP8J_AUTHORITY_SEAL}",
        f"meta\trole\t{wp8k.ROLE_NAME}",
        "meta\tclaim-status\tnot-admitted",
    )
    if tuple(lines[1:7]) != expected_metadata:
        raise CandidateEvidenceError("candidate session metadata drifted")
    build = lines[7].split("\t") if len(lines) > 7 else []
    if (
        len(build) != 6
        or build[0] != "build"
        or build[1] != binary_hash
        or build[2] != toolchain_hash
        or _positive(build[3], "compile interval") <= 0
        or _positive(build[4], "specialization interval") <= 0
        or build[5] != str(code_size)
    ):
        raise CandidateEvidenceError("candidate build receipt drifted")
    index = 8
    if index >= len(lines) - 1:
        raise CandidateEvidenceError("candidate session lacks warmup extent")
    warmup_header = lines[index].split("\t")
    if len(warmup_header) != 2 or warmup_header[0] != "warmups" or not POSITIVE_RE.fullmatch(warmup_header[1]):
        raise CandidateEvidenceError("candidate warmup header is malformed")
    warmup_total = int(warmup_header[1])
    if warmup_total > len(wp8k.KERNELS) * wp8k.MAX_WARMUP_INVOCATIONS:
        raise CandidateEvidenceError("candidate warmup extent exceeds its ceiling")
    index += 1
    warmup_facts = []
    consumed_warmups = 0
    for ordinal, _name, oracle in wp8k.KERNELS:
        count = 0
        cumulative = 0
        while index < len(lines) - 1 and lines[index].startswith(f"warmup\t{ordinal}\t"):
            fields = lines[index].split("\t")
            count += 1
            if len(fields) != 7 or fields[2] != str(count):
                raise CandidateEvidenceError("candidate warmup order drifted")
            duration = _positive(fields[3], "warmup duration")
            _checksum(fields[4], oracle)
            envelope = _positive(fields[5], "warmup envelope")
            _positive(fields[6], "warmup RSS")
            if envelope <= duration:
                raise CandidateEvidenceError("candidate warmup envelope is not larger than runtime")
            cumulative += duration
            consumed_warmups += 1
            index += 1
        if count == 0 or cumulative < wp8k.WARMUP_MINIMUM_NS:
            raise CandidateEvidenceError("candidate warmup completeness drifted")
        warmup_facts.append((count, cumulative))
    if consumed_warmups != warmup_total:
        raise CandidateEvidenceError("candidate warmup count differs from its header")
    if index >= len(lines) - 1:
        raise CandidateEvidenceError("candidate session lacks sample extent")
    sample_header = lines[index].split("\t")
    expected_sample_count = len(wp8k.KERNELS) * wp8k.SAMPLE_COUNT
    if tuple(sample_header) != ("samples", str(expected_sample_count)):
        raise CandidateEvidenceError("candidate sample header drifted")
    index += 1
    statistics = []
    for kernel_index, (ordinal, name, oracle) in enumerate(wp8k.KERNELS):
        durations = []
        for sample_ordinal in range(1, wp8k.SAMPLE_COUNT + 1):
            if index >= len(lines) - 1:
                raise CandidateEvidenceError("candidate sample set is truncated")
            fields = lines[index].split("\t")
            if len(fields) != 7 or tuple(fields[1:3]) != (ordinal, str(sample_ordinal)):
                raise CandidateEvidenceError("candidate sample order drifted")
            duration = _positive(fields[3], "sample duration")
            _checksum(fields[4], oracle)
            envelope = _positive(fields[5], "sample envelope")
            _positive(fields[6], "sample RSS")
            if envelope <= duration:
                raise CandidateEvidenceError("candidate sample envelope is not larger than runtime")
            durations.append(duration)
            index += 1
        median_num, median_den = _median(durations)
        warmup_count, warmup_ns = warmup_facts[kernel_index]
        statistics.append(
            KernelStatistic(
                ordinal,
                name,
                oracle,
                warmup_count,
                warmup_ns,
                len(durations),
                min(durations),
                max(durations),
                sum(durations),
                median_num,
                median_den,
            )
        )
    if index != len(lines) - 1:
        raise CandidateEvidenceError("candidate session contains trailing rows")
    return Session(root_fields[1], binary_hash, toolchain_hash, tuple(statistics))


def verify_reproduction(bundle: Path, manifest: Manifest) -> None:
    lines = _canonical(
        _read_regular(bundle / "REPRODUCE.tsv", "candidate reproduction receipt"),
        "candidate reproduction receipt",
    )
    expected = (
        "NAUX-S4-REGISTER-RESIDENCY-REPRODUCTION\t1",
        f"source-commit\t{manifest.source_commit}",
        f"runner-authority\t{WP8K_AUTHORITY_SEAL}",
        f"host-attestation-root\t{manifest.host_attestation}",
    )
    if len(lines) != 6 or tuple(lines[:4]) != expected:
        raise CandidateEvidenceError("candidate reproduction authority drifted")
    origin = lines[4].split("\t")
    if len(origin) != 2 or origin[0] != "original-host-attestation" or not origin[1]:
        raise CandidateEvidenceError("candidate reproduction origin is malformed")
    if lines[5] != "policy\tnew-eligible-attestation-and-new-output-required-for-each-run":
        raise CandidateEvidenceError("candidate reproduction policy drifted")


def _evidence_report(
    admission: Admission,
    manifest: Manifest,
    session: Session,
) -> tuple[bytes, str]:
    rows = [
        EVIDENCE_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"runner-authority\t{WP8K_AUTHORITY_SEAL}",
        f"carrier-authority\t{WP8J_AUTHORITY_SEAL}",
        f"bundle-root\t{manifest.root}",
        f"session-root\t{session.root}",
        f"host-attestation\t{manifest.host_attestation}",
        f"source-commit\t{manifest.source_commit}",
        f"role\t{wp8k.ROLE_NAME}",
        f"binary-hash\t{session.binary_hash}",
        f"toolchain-hash\t{session.toolchain_hash}",
    ]
    rows.extend(
        f"kernel\t{item.ordinal}\t{item.name}\t{item.oracle}\t"
        f"{item.warmup_count}\t{item.warmup_ns}\t{item.sample_count}\t"
        f"{item.minimum_ns}\t{item.maximum_ns}\t{item.total_ns}\t"
        f"{item.median_num}\t{item.median_den}"
        for item in session.statistics
    )
    rows.extend(("samples\t120", "claim-status\tnot-admitted"))
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(EVIDENCE_DOMAIN + body)
    return body + f"evidence-root\t{root}\n".encode(), root


def replay_bundle(path: Path, admission: Admission) -> Replay:
    bundle = _bundle_directory(path)
    manifest = parse_manifest(bundle)
    verify_inventory(bundle, manifest)
    retained = wp8k.parse_retained_host(
        bundle / "HOST-ATTESTATION.tsv", admission.runner
    )
    if (
        retained.report_root != manifest.host_attestation
        or retained.commit != manifest.source_commit
    ):
        raise CandidateEvidenceError("candidate host report differs from manifest")
    binary_hash, code_size = artifact_identity(bundle, admission)
    toolchain_hash = toolchain_identity(bundle, manifest)
    session = parse_session(
        bundle, manifest, binary_hash, code_size, toolchain_hash
    )
    verify_reproduction(bundle, manifest)
    final_manifest = parse_manifest(bundle)
    verify_inventory(bundle, final_manifest)
    if final_manifest != manifest:
        raise CandidateEvidenceError("candidate bundle changed during replay")
    evidence, evidence_root = _evidence_report(admission, manifest, session)
    return Replay(manifest, session, evidence, evidence_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--bundle", type=Path)
    arguments = parser.parse_args(argv)
    try:
        admission = validate(arguments.root)
        if arguments.bundle is None:
            sys.stdout.buffer.write(admission.static_report)
        else:
            sys.stdout.buffer.write(replay_bundle(arguments.bundle, admission).evidence)
        return 0
    except (
        CandidateEvidenceError,
        wp8k.CandidateRunnerError,
        wp8k.wp7c.RunnerError,
        wp8k.wp8i.CandidateHostError,
        wp8k.wp8j.CandidateTimingError,
        OSError,
        ValueError,
    ) as error:
        print(f"S4-WP8L validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
