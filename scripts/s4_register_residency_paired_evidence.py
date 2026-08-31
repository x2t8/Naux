#!/usr/bin/env python3
"""Validate or replay S4-WP8N same-session paired evidence."""

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

import s4_register_residency_paired_runner as wp8m


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PAIRED-EVIDENCE-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PAIRED-EVIDENCE-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PAIRED-EVIDENCE-REPORT\t1"
EVIDENCE_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PAIRED-EVIDENCE\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-paired-evidence:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-paired-evidence:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-paired-evidence:report:v1\0"
EVIDENCE_DOMAIN = b"NAUX:s4-register-residency-paired-evidence:result:v1\0"
CONTRACT_SEAL = "e23a2d2386f319efa6941fb8f7c4355417b00482ef51048b9f2b00a7c907e424"
WP8M_AUTHORITY_SEAL = "1426d1d363763006a4f8316c8561f179cedcd7df38467778d6fbb577c421a191"
WP8J_AUTHORITY_SEAL = wp8m.WP8J_AUTHORITY_SEAL
WP7B_AUTHORITY_SEAL = wp8m.WP7B_AUTHORITY_SEAL
BUNDLE_DOMAIN = wp8m.BUNDLE_DOMAIN
SESSION_DOMAIN = wp8m.SESSION_DOMAIN
TOOLCHAIN_RECEIPT_DOMAIN = wp8m.TOOLCHAIN_DOMAIN
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
    ("parent-paired-runner-authority", WP8M_AUTHORITY_SEAL),
    ("parent-baseline-carrier-authority", WP7B_AUTHORITY_SEAL),
    ("parent-candidate-carrier-authority", WP8J_AUTHORITY_SEAL),
    ("status", "paired-evidence-replay-structurally-admitted"),
    ("input", "exact-wp8m-paired-raw-bundle-v1"),
    ("default-mode", "static-no-bundle-no-host-no-clock-no-execution"),
    ("replay-mode", "explicit-read-only"),
    ("inventory-policy", "exact-twelve-payload-files-and-manifest"),
    ("schedule-policy", "four-kernels-exact30-pairs-odd-ab-even-ba"),
    ("statistics-policy", "exact-integer-paired-reduction-no-float"),
    ("comparison-policy", "totals-medians-paired-deltas-wins-ties-losses-ratio"),
    ("claim-status", "not-admitted"),
    ("target", "x86_64-unknown-linux-gnu"),
)
GATES = (
    ("01", "static-isolation", "required", "no-bundle-no-host-no-clock-no-execution"),
    ("02", "bundle-root", "required", "exact-wp8m-manifest-and-inventory"),
    ("03", "host-attestation", "required", "exact-eligible-retained-wp8i-report"),
    ("04", "session-root", "required", "exact-paired-warmups-and240-sample-runs"),
    ("05", "artifact-identity", "required", "exact-four-wp7b-and-four-wp8j-images"),
    ("06", "toolchain-identity", "required", "same-exact-portable-receipts-both-roles"),
    ("07", "schedule", "required", "odd-ab-even-ba-complete-no-drop-no-retry"),
    ("08", "result-parity", "required", "every-checksum-matches-frozen-oracle"),
    ("09", "statistics", "required", "exact-clock-free-paired-reduction-only"),
    ("10", "reproduction", "required", "exact-source-host-runner-binding"),
    ("11", "claim-boundary", "required", "replay-never-self-admits-claim"),
)
CLOSURES = (
    ("01", "paired-raw-bundle-verifier-unavailable", "closed", "wp8n-independent-replay"),
    ("02", "baseline-candidate-comparison-unavailable", "closed", "wp8n-exact-paired-reduction"),
)
BLOCKERS = (
    ("01", "eligible-paired-raw-bundle-unavailable"),
    ("02", "paired-inference-threshold-authority-unavailable"),
    ("03", "performance-claim-authority-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8N"),
    ("authority-id", "s4-register-residency-paired-evidence-v1"),
    ("status", "paired-evidence-replay-structurally-admitted"),
    ("claim-status", "not-admitted"),
    ("execution-policy", "forbidden"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-paired-evidence.yml",
    "distribution/s4-performance/WP8N-PAIRED-EVIDENCE.tsv",
    "distribution/s4-performance/WP8N-NONCLAIMS.md",
    "distribution/s4-performance/WP8N-README.md",
    "scripts/s4_register_residency_paired_evidence.py",
    "scripts/tests/test_s4_register_residency_paired_evidence_replay.py",
    "scripts/tests/test_s4_register_residency_paired_evidence_static.py",
)
CORE_BUNDLE_FILES = (
    "HOST-ATTESTATION.tsv",
    "RAW-PAIRED-SESSION.tsv",
    "TOOLCHAINS.tsv",
    "REPRODUCE.tsv",
)
ARTIFACT_FILES = tuple(
    f"artifacts/{directory}/{ordinal}-{name}"
    for directory in ("baseline", "candidate")
    for ordinal, name, _oracle in wp8m.KERNELS
)
EXPECTED_BUNDLE_FILES = CORE_BUNDLE_FILES + ARTIFACT_FILES


class PairedEvidenceError(RuntimeError):
    """A fail-closed WP8N validation or replay error."""


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
    runner: wp8m.Admission
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
class KernelComparison:
    ordinal: str
    name: str
    oracle: int
    warmup_pairs: int
    baseline_warmup_ns: int
    candidate_warmup_ns: int
    sample_pairs: int
    baseline_total_ns: int
    candidate_total_ns: int
    delta_total_ns: int
    baseline_median_num: int
    baseline_median_den: int
    candidate_median_num: int
    candidate_median_den: int
    delta_median_num: int
    delta_median_den: int
    candidate_wins: int
    ties: int
    candidate_losses: int
    total_ratio_num: int
    total_ratio_den: int


@dataclass(frozen=True)
class Session:
    root: str
    binary_hashes: tuple[tuple[str, str], ...]
    toolchain_hash: str
    comparisons: tuple[KernelComparison, ...]


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
        raise PairedEvidenceError(f"cannot inspect {label}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise PairedEvidenceError(f"{label} is not a bounded regular file")
    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            raw = handle.read(maximum + 1)
            after = os.fstat(handle.fileno())
        rebound = path.lstat()
    except OSError as error:
        raise PairedEvidenceError(f"cannot read {label}") from error
    if (
        (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        or (opened.st_dev, opened.st_ino, opened.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or len(raw) != after.st_size
        or stat.S_ISLNK(rebound.st_mode)
        or (rebound.st_dev, rebound.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise PairedEvidenceError(f"{label} changed while read")
    return raw


def _canonical(raw: bytes, label: str) -> list[str]:
    if not raw or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise PairedEvidenceError(f"{label} has invalid canonical extent")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise PairedEvidenceError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise PairedEvidenceError(f"{label} contains blank or padded rows")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    raw = _read_regular(path, path.name)
    lines = _canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise PairedEvidenceError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]) or _sha256(domain + body) != fields[1]:
        raise PairedEvidenceError(f"{path.name} seal drifted")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL:
        raise PairedEvidenceError("WP8N contract identity drifted")
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
        raise PairedEvidenceError("WP8N contract rows drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    prefix = [f"meta\t{key}\t{value}" for key, value in AUTHORITY_METADATA]
    prefix.extend((
        f"component\tpaired-evidence-contract\tdistribution/s4-performance/WP8N-PAIRED-EVIDENCE.tsv\t{contract_seal}",
        f"parent\tpaired-runner-authority\tdistribution/s4-performance/WP8M-AUTHORITY.tsv\t{WP8M_AUTHORITY_SEAL}",
        f"parent\tbaseline-carrier-authority\tdistribution/s4-performance/WP7B-AUTHORITY.tsv\t{WP7B_AUTHORITY_SEAL}",
        f"parent\tcandidate-carrier-authority\tdistribution/s4-performance/WP8J-AUTHORITY.tsv\t{WP8J_AUTHORITY_SEAL}",
    ))
    if rows[: len(prefix)] != prefix:
        raise PairedEvidenceError("WP8N authority metadata or parent binding drifted")
    records = []
    for row in rows[len(prefix):]:
        fields = row.split("\t")
        if (
            len(fields) != 6
            or fields[0] != "file"
            or not MODE_RE.fullmatch(fields[1])
            or not UINT_RE.fullmatch(fields[2])
            or not HASH_RE.fullmatch(fields[3])
            or fields[4] not in EXPECTED_FILES
            or fields[5] != "paired-evidence-replay"
        ):
            raise PairedEvidenceError("WP8N authority file row is malformed")
        records.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise PairedEvidenceError("WP8N authority inventory drifted")
    return Authority(tuple(records), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        raw = _read_regular(path, record.path)
        mode = stat.S_IFREG | stat.S_IMODE(path.lstat().st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise PairedEvidenceError(f"bound WP8N file drifted: {record.path}")


def _static_report(contract: Contract, authority: Authority) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"paired-runner-authority\t{WP8M_AUTHORITY_SEAL}",
        "status\tpaired-evidence-replay-structurally-admitted",
        "mode\tstatic-no-bundle-no-host-no-clock-no-execution",
        "bundle-status\texternal-eligible-paired-bundle-required",
        "claim-status\tnot-admitted",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    runner = wp8m.validate(root)
    if (
        runner.authority.seal != WP8M_AUTHORITY_SEAL
        or runner.candidate.carrier.authority.seal != WP8J_AUTHORITY_SEAL
        or runner.candidate.carrier.wrapper.authority.seal != WP7B_AUTHORITY_SEAL
    ):
        raise PairedEvidenceError("WP8N parent authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP8N-PAIRED-EVIDENCE.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP8N-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    report, report_root = _static_report(contract, authority)
    return Admission(contract, authority, runner, report, report_root)


def _bundle_directory(path: Path) -> Path:
    absolute = path.expanduser().absolute()
    try:
        metadata = absolute.lstat()
    except OSError as error:
        raise PairedEvidenceError("cannot inspect paired bundle") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise PairedEvidenceError("paired bundle is not a real directory")
    return absolute.resolve(strict=True)


def _safe_relative(value: str) -> None:
    if not PATH_RE.fullmatch(value):
        raise PairedEvidenceError("paired bundle path token is malformed")
    path = Path(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise PairedEvidenceError("paired bundle path is absolute or traversing")


def parse_manifest(bundle: Path) -> Manifest:
    raw = _read_regular(bundle / "MANIFEST.tsv", "paired bundle manifest")
    lines = _canonical(raw, "paired bundle manifest")
    if lines[0] != wp8m.BUNDLE_MAGIC or not lines[-1].startswith("bundle-root\t"):
        raise PairedEvidenceError("paired manifest magic or shape drifted")
    body = raw[: -(len(lines[-1]) + 1)]
    root_fields = lines[-1].split("\t")
    if (
        len(root_fields) != 2
        or not HASH_RE.fullmatch(root_fields[1])
        or _sha256(BUNDLE_DOMAIN + body) != root_fields[1]
    ):
        raise PairedEvidenceError("paired manifest root mismatch")
    metadata = []
    index = 1
    while index < len(lines) - 1 and lines[index].startswith("meta\t"):
        fields = lines[index].split("\t")
        if len(fields) != 3:
            raise PairedEvidenceError("paired manifest metadata is malformed")
        metadata.append((fields[1], fields[2]))
        index += 1
    expected_keys = (
        "runner-authority", "host-attestation", "session-root", "source-commit",
        "schedule", "claim-status", "file-count",
    )
    if tuple(key for key, _value in metadata) != expected_keys:
        raise PairedEvidenceError("paired manifest metadata order drifted")
    values = dict(metadata)
    if (
        values["runner-authority"] != WP8M_AUTHORITY_SEAL
        or not HASH_RE.fullmatch(values["host-attestation"])
        or not HASH_RE.fullmatch(values["session-root"])
        or not COMMIT_RE.fullmatch(values["source-commit"])
        or values["schedule"] != "kernel-major-odd-ab-even-ba"
        or values["claim-status"] != "not-admitted"
        or values["file-count"] != str(len(EXPECTED_BUNDLE_FILES))
    ):
        raise PairedEvidenceError("paired manifest authority or identity drifted")
    files = []
    while index < len(lines) - 1:
        fields = lines[index].split("\t")
        if (
            len(fields) != 4
            or fields[0] != "file"
            or not POSITIVE_RE.fullmatch(fields[2])
            or not HASH_RE.fullmatch(fields[3])
        ):
            raise PairedEvidenceError("paired manifest file row is malformed")
        _safe_relative(fields[1])
        files.append((fields[1], int(fields[2]), fields[3]))
        index += 1
    if tuple(path for path, _size, _digest in files) != EXPECTED_BUNDLE_FILES:
        raise PairedEvidenceError("paired manifest file inventory drifted")
    return Manifest(
        root_fields[1], values["host-attestation"], values["session-root"],
        values["source-commit"], tuple(files),
    )


def verify_inventory(bundle: Path, manifest: Manifest) -> None:
    try:
        root_entries = {entry.name for entry in bundle.iterdir()}
    except OSError as error:
        raise PairedEvidenceError("cannot enumerate paired bundle") from error
    if root_entries != {"MANIFEST.tsv", *CORE_BUNDLE_FILES, "artifacts"}:
        raise PairedEvidenceError("paired bundle root inventory drifted")
    artifacts = bundle / "artifacts"
    try:
        metadata = artifacts.lstat()
        role_entries = {entry.name for entry in artifacts.iterdir()}
    except OSError as error:
        raise PairedEvidenceError("cannot enumerate paired artifacts") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or role_entries != {"baseline", "candidate"}:
        raise PairedEvidenceError("paired artifact role inventory drifted")
    for directory in ("baseline", "candidate"):
        role_path = artifacts / directory
        role_metadata = role_path.lstat()
        if stat.S_ISLNK(role_metadata.st_mode) or not stat.S_ISDIR(role_metadata.st_mode):
            raise PairedEvidenceError("paired artifact role path is not a real directory")
        expected = {
            f"{ordinal}-{name}" for ordinal, name, _oracle in wp8m.KERNELS
        }
        if {entry.name for entry in role_path.iterdir()} != expected:
            raise PairedEvidenceError("paired artifact kernel inventory drifted")
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
            raise PairedEvidenceError(f"paired bundle file drifted: {relative}")
    if stat.S_IMODE((bundle / "MANIFEST.tsv").lstat().st_mode) != 0o600:
        raise PairedEvidenceError("paired manifest mode drifted")


def artifact_identities(
    bundle: Path, admission: Admission
) -> tuple[dict[str, str], dict[str, int]]:
    contracts = {
        wp8m.BASELINE_ROLE: admission.runner.candidate.carrier.wrapper.contract.records,
        wp8m.CANDIDATE_ROLE: admission.runner.candidate.carrier.contract.records,
    }
    directories = {wp8m.BASELINE_ROLE: "baseline", wp8m.CANDIDATE_ROLE: "candidate"}
    identities = {}
    sizes = {}
    for role, _name, _status, _owner in wp8m.ROLES:
        records = contracts[role]
        if len(records) != len(wp8m.KERNELS):
            raise PairedEvidenceError("paired carrier artifact extent drifted")
        rows = []
        total = 0
        for record, (ordinal, name, oracle) in zip(records, wp8m.KERNELS, strict=True):
            path = bundle / f"artifacts/{directories[role]}/{ordinal}-{name}"
            raw = _read_regular(path, f"paired artifact {role}/{ordinal}", MAX_ARTIFACT_BYTES)
            if (
                record.ordinal != int(ordinal)
                or record.name != name
                or record.oracle != oracle
                or len(raw) != record.elf_bytes
                or _sha256(raw) != record.elf_hash
            ):
                raise PairedEvidenceError(f"paired artifact {role}/{ordinal} differs from its carrier")
            rows.append(f"artifact\t{ordinal}\t{record.elf_hash}\t{record.elf_bytes}\n")
            total += len(raw)
        identities[role] = _sha256(BINARY_DOMAIN + "".join(rows).encode())
        sizes[role] = total
    return identities, sizes


def toolchain_identity(bundle: Path, manifest: Manifest) -> str:
    raw = _read_regular(bundle / "TOOLCHAINS.tsv", "paired toolchain receipt")
    lines = _canonical(raw, "paired toolchain receipt")
    if lines[0] != wp8m.TOOLCHAIN_MAGIC or not lines[-1].startswith("toolchain-root\t"):
        raise PairedEvidenceError("paired toolchain receipt shape drifted")
    body = raw[: -(len(lines[-1]) + 1)]
    root_fields = lines[-1].split("\t")
    if (
        len(root_fields) != 2
        or not HASH_RE.fullmatch(root_fields[1])
        or _sha256(TOOLCHAIN_RECEIPT_DOMAIN + body) != root_fields[1]
    ):
        raise PairedEvidenceError("paired toolchain receipt root mismatch")
    expected_metadata = (
        f"meta\trunner-authority\t{WP8M_AUTHORITY_SEAL}",
        f"meta\tsource-commit\t{manifest.source_commit}",
        "meta\tclaim-status\tnot-admitted",
    )
    if tuple(lines[1:4]) != expected_metadata or len(lines[4:-1]) != 4:
        raise PairedEvidenceError("paired toolchain metadata or extent drifted")
    role_records: dict[str, list[tuple[str, ...]]] = {
        wp8m.BASELINE_ROLE: [], wp8m.CANDIDATE_ROLE: [],
    }
    expected = (
        (wp8m.BASELINE_ROLE, "01", "cargo"),
        (wp8m.BASELINE_ROLE, "02", "rustc"),
        (wp8m.CANDIDATE_ROLE, "01", "cargo"),
        (wp8m.CANDIDATE_ROLE, "02", "rustc"),
    )
    for line, wanted in zip(lines[4:-1], expected, strict=True):
        fields = line.split("\t")
        if (
            len(fields) != 8
            or tuple(fields[1:4]) != wanted
            or not fields[4]
            or any(character in fields[4] for character in "\0\r\n\t")
            or not HASH_RE.fullmatch(fields[5])
            or not HASH_RE.fullmatch(fields[6])
        ):
            raise PairedEvidenceError("paired toolchain row is malformed")
        try:
            version = bytes.fromhex(fields[7])
        except ValueError as error:
            raise PairedEvidenceError("paired toolchain version is not hex") from error
        if not version or version.hex() != fields[7] or _sha256(version) != fields[6]:
            raise PairedEvidenceError("paired toolchain version identity drifted")
        role_records[fields[1]].append(tuple(fields[3:8]))
    baseline = tuple(role_records[wp8m.BASELINE_ROLE])
    candidate = tuple(role_records[wp8m.CANDIDATE_ROLE])
    if baseline != candidate:
        raise PairedEvidenceError("baseline and candidate toolchain receipts differ")
    aggregate = b"".join(
        f"tool\t{name}\t{executable_hash}\t{version_hash}\n".encode()
        for name, _path, executable_hash, version_hash, _version_hex in baseline
    )
    return _sha256(TOOLCHAIN_DOMAIN + aggregate)


def _positive(value: str, label: str) -> int:
    if not POSITIVE_RE.fullmatch(value):
        raise PairedEvidenceError(f"{label} is not a positive integer")
    return int(value)


def _checksum(value: str, oracle: int) -> int:
    if not INT_RE.fullmatch(value) or int(value) != oracle:
        raise PairedEvidenceError("paired checksum differs from its frozen oracle")
    return int(value)


def _fraction(numerator: int, denominator: int) -> tuple[int, int]:
    if denominator <= 0:
        raise PairedEvidenceError("paired statistic denominator is not positive")
    divisor = math.gcd(abs(numerator), denominator)
    return numerator // divisor, denominator // divisor


def _median(values: list[int]) -> tuple[int, int]:
    if not values:
        raise PairedEvidenceError("paired median input is empty")
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle], 1
    return _fraction(ordered[middle - 1] + ordered[middle], 2)


def _parse_pair(
    lines: list[str],
    index: int,
    tag: str,
    kernel: str,
    ordinal: int,
    oracle: int,
) -> tuple[int, int, int]:
    width = 6 if tag == "warmup" else 2
    rendered = f"{ordinal:0{width}d}"
    order = "AB" if ordinal % 2 else "BA"
    if index >= len(lines) - 1 or lines[index] != f"{tag}-pair\t{kernel}\t{rendered}\t{order}":
        raise PairedEvidenceError("paired AB/BA schedule drifted")
    index += 1
    role_order = (
        (wp8m.BASELINE_ROLE, wp8m.CANDIDATE_ROLE)
        if order == "AB" else (wp8m.CANDIDATE_ROLE, wp8m.BASELINE_ROLE)
    )
    statuses = {role: status for role, _name, status, _owner in wp8m.ROLES}
    durations = {}
    for position, role in enumerate(role_order, 1):
        if index >= len(lines) - 1:
            raise PairedEvidenceError("paired invocation set is truncated")
        fields = lines[index].split("\t")
        if (
            len(fields) != 10
            or tuple(fields[:5]) != (f"{tag}-run", kernel, rendered, str(position), role)
            or fields[9] != statuses[role]
        ):
            raise PairedEvidenceError("paired invocation order or role drifted")
        duration = _positive(fields[5], f"{tag} duration")
        _checksum(fields[6], oracle)
        envelope = _positive(fields[7], f"{tag} envelope")
        _positive(fields[8], f"{tag} RSS")
        if envelope <= duration:
            raise PairedEvidenceError("paired envelope is not larger than runtime")
        durations[role] = duration
        index += 1
    return index, durations[wp8m.BASELINE_ROLE], durations[wp8m.CANDIDATE_ROLE]


def parse_session(
    bundle: Path,
    manifest: Manifest,
    binary_hashes: dict[str, str],
    code_sizes: dict[str, int],
    toolchain_hash: str,
) -> Session:
    raw = _read_regular(bundle / "RAW-PAIRED-SESSION.tsv", "paired raw session")
    lines = _canonical(raw, "paired raw session")
    if lines[0] != wp8m.SESSION_MAGIC or not lines[-1].startswith("session-root\t"):
        raise PairedEvidenceError("paired session shape drifted")
    body = raw[: -(len(lines[-1]) + 1)]
    root_fields = lines[-1].split("\t")
    if (
        len(root_fields) != 2
        or not HASH_RE.fullmatch(root_fields[1])
        or _sha256(SESSION_DOMAIN + body) != root_fields[1]
        or root_fields[1] != manifest.session_root
    ):
        raise PairedEvidenceError("paired session root mismatch")
    expected_metadata = (
        f"meta\trunner-authority\t{WP8M_AUTHORITY_SEAL}",
        f"meta\thost-attestation\t{manifest.host_attestation}",
        f"meta\tsource-commit\t{manifest.source_commit}",
        f"meta\tbaseline-carrier-authority\t{WP7B_AUTHORITY_SEAL}",
        f"meta\tcandidate-carrier-authority\t{WP8J_AUTHORITY_SEAL}",
        "meta\tschedule\tkernel-major-odd-ab-even-ba",
        "meta\tclaim-status\tnot-admitted",
    )
    if tuple(lines[1:8]) != expected_metadata:
        raise PairedEvidenceError("paired session metadata drifted")
    index = 8
    for role, name, _status, _owner in wp8m.ROLES:
        if index >= len(lines) - 1:
            raise PairedEvidenceError("paired session lacks build receipts")
        fields = lines[index].split("\t")
        if (
            len(fields) != 8
            or tuple(fields[:3]) != ("build", role, name)
            or fields[3] != binary_hashes[role]
            or fields[4] != toolchain_hash
            or _positive(fields[5], "compile interval") <= 0
            or _positive(fields[6], "specialization interval") <= 0
            or fields[7] != str(code_sizes[role])
        ):
            raise PairedEvidenceError("paired build receipt drifted")
        index += 1
    if index >= len(lines) - 1:
        raise PairedEvidenceError("paired session lacks warmup header")
    warmup_header = lines[index].split("\t")
    if len(warmup_header) != 2 or warmup_header[0] != "warmup-pairs" or not POSITIVE_RE.fullmatch(warmup_header[1]):
        raise PairedEvidenceError("paired warmup header is malformed")
    warmup_total = int(warmup_header[1])
    if warmup_total > len(wp8m.KERNELS) * wp8m.MAX_WARMUP_PAIRS:
        raise PairedEvidenceError("paired warmup extent exceeds its ceiling")
    index += 1
    warmup_facts = []
    consumed = 0
    for kernel, _name, oracle in wp8m.KERNELS:
        ordinal = 1
        baseline_total = 0
        candidate_total = 0
        before_last = (0, 0)
        while index < len(lines) - 1 and lines[index].startswith(f"warmup-pair\t{kernel}\t"):
            before_last = (baseline_total, candidate_total)
            index, baseline, candidate = _parse_pair(
                lines, index, "warmup", kernel, ordinal, oracle
            )
            baseline_total += baseline
            candidate_total += candidate
            ordinal += 1
            consumed += 1
        count = ordinal - 1
        if (
            count == 0
            or baseline_total < wp8m.WARMUP_MINIMUM_NS
            or candidate_total < wp8m.WARMUP_MINIMUM_NS
            or min(before_last) >= wp8m.WARMUP_MINIMUM_NS
        ):
            raise PairedEvidenceError("paired warmup completeness or stopping point drifted")
        warmup_facts.append((count, baseline_total, candidate_total))
    if consumed != warmup_total:
        raise PairedEvidenceError("paired warmup count differs from its header")
    if index >= len(lines) - 1 or lines[index] != f"sample-pairs\t{len(wp8m.KERNELS) * wp8m.SAMPLE_PAIR_COUNT}":
        raise PairedEvidenceError("paired sample header drifted")
    index += 1
    comparisons = []
    for kernel_index, (kernel, name, oracle) in enumerate(wp8m.KERNELS):
        baseline_values = []
        candidate_values = []
        for ordinal in range(1, wp8m.SAMPLE_PAIR_COUNT + 1):
            index, baseline, candidate = _parse_pair(
                lines, index, "sample", kernel, ordinal, oracle
            )
            baseline_values.append(baseline)
            candidate_values.append(candidate)
        deltas = [candidate - baseline for baseline, candidate in zip(baseline_values, candidate_values, strict=True)]
        baseline_total = sum(baseline_values)
        candidate_total = sum(candidate_values)
        warmup_count, baseline_warmup, candidate_warmup = warmup_facts[kernel_index]
        baseline_median = _median(baseline_values)
        candidate_median = _median(candidate_values)
        delta_median = _median(deltas)
        ratio = _fraction(baseline_total, candidate_total)
        comparisons.append(KernelComparison(
            kernel, name, oracle, warmup_count, baseline_warmup, candidate_warmup,
            len(baseline_values), baseline_total, candidate_total,
            candidate_total - baseline_total,
            baseline_median[0], baseline_median[1],
            candidate_median[0], candidate_median[1],
            delta_median[0], delta_median[1],
            sum(candidate < baseline for baseline, candidate in zip(baseline_values, candidate_values, strict=True)),
            sum(candidate == baseline for baseline, candidate in zip(baseline_values, candidate_values, strict=True)),
            sum(candidate > baseline for baseline, candidate in zip(baseline_values, candidate_values, strict=True)),
            ratio[0], ratio[1],
        ))
    if index != len(lines) - 1:
        raise PairedEvidenceError("paired session contains trailing rows")
    return Session(
        root_fields[1], tuple((role, binary_hashes[role]) for role, *_rest in wp8m.ROLES),
        toolchain_hash, tuple(comparisons),
    )


def verify_reproduction(bundle: Path, manifest: Manifest) -> None:
    lines = _canonical(
        _read_regular(bundle / "REPRODUCE.tsv", "paired reproduction receipt"),
        "paired reproduction receipt",
    )
    expected = (
        "NAUX-S4-REGISTER-RESIDENCY-PAIRED-REPRODUCTION\t1",
        f"source-commit\t{manifest.source_commit}",
        f"runner-authority\t{WP8M_AUTHORITY_SEAL}",
        f"host-attestation-root\t{manifest.host_attestation}",
    )
    if len(lines) != 6 or tuple(lines[:4]) != expected:
        raise PairedEvidenceError("paired reproduction authority drifted")
    origin = lines[4].split("\t")
    if len(origin) != 2 or origin[0] != "original-host-attestation" or not origin[1]:
        raise PairedEvidenceError("paired reproduction origin is malformed")
    if lines[5] != "policy\tnew-eligible-attestation-and-new-output-required-for-each-run":
        raise PairedEvidenceError("paired reproduction policy drifted")


def _evidence_report(
    admission: Admission, manifest: Manifest, session: Session
) -> tuple[bytes, str]:
    rows = [
        EVIDENCE_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"runner-authority\t{WP8M_AUTHORITY_SEAL}",
        f"baseline-carrier-authority\t{WP7B_AUTHORITY_SEAL}",
        f"candidate-carrier-authority\t{WP8J_AUTHORITY_SEAL}",
        f"bundle-root\t{manifest.root}",
        f"session-root\t{session.root}",
        f"host-attestation\t{manifest.host_attestation}",
        f"source-commit\t{manifest.source_commit}",
        f"toolchain-hash\t{session.toolchain_hash}",
    ]
    rows.extend(f"binary-hash\t{role}\t{digest}" for role, digest in session.binary_hashes)
    rows.extend(
        f"kernel\t{item.ordinal}\t{item.name}\t{item.oracle}\t{item.warmup_pairs}\t"
        f"{item.baseline_warmup_ns}\t{item.candidate_warmup_ns}\t{item.sample_pairs}\t"
        f"{item.baseline_total_ns}\t{item.candidate_total_ns}\t{item.delta_total_ns}\t"
        f"{item.baseline_median_num}\t{item.baseline_median_den}\t"
        f"{item.candidate_median_num}\t{item.candidate_median_den}\t"
        f"{item.delta_median_num}\t{item.delta_median_den}\t"
        f"{item.candidate_wins}\t{item.ties}\t{item.candidate_losses}\t"
        f"{item.total_ratio_num}\t{item.total_ratio_den}"
        for item in session.comparisons
    )
    rows.extend(("sample-pairs\t120", "sample-invocations\t240", "claim-status\tnot-admitted"))
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(EVIDENCE_DOMAIN + body)
    return body + f"evidence-root\t{root}\n".encode(), root


def replay_bundle(path: Path, admission: Admission) -> Replay:
    bundle = _bundle_directory(path)
    manifest = parse_manifest(bundle)
    verify_inventory(bundle, manifest)
    retained = wp8m.wp8k.parse_retained_host(
        bundle / "HOST-ATTESTATION.tsv", admission.runner.candidate
    )
    if retained.report_root != manifest.host_attestation or retained.commit != manifest.source_commit:
        raise PairedEvidenceError("paired host report differs from manifest")
    binary_hashes, code_sizes = artifact_identities(bundle, admission)
    toolchain_hash = toolchain_identity(bundle, manifest)
    session = parse_session(
        bundle, manifest, binary_hashes, code_sizes, toolchain_hash
    )
    verify_reproduction(bundle, manifest)
    final_manifest = parse_manifest(bundle)
    verify_inventory(bundle, final_manifest)
    if final_manifest != manifest:
        raise PairedEvidenceError("paired bundle changed during replay")
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
        PairedEvidenceError,
        wp8m.PairedRunnerError,
        wp8m.wp8k.CandidateRunnerError,
        wp8m.wp7c.RunnerError,
        OSError,
        ValueError,
    ) as error:
        print(f"S4-WP8N validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
