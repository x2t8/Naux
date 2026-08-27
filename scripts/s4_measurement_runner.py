#!/usr/bin/env python3
"""Validate or explicitly run the fail-closed S4-WP7C acquisition runner."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import math
import os
import re
import resource
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import s4_c_timing_carriers as wp7b_c
import s4_measurement_evidence as wp7a
import s4_residual_timing as wp7b_naux


CONTRACT_MAGIC = "NAUX-S4-MEASUREMENT-RUNNER-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-MEASUREMENT-RUNNER-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-MEASUREMENT-RUNNER-REPORT\t1"
SESSION_MAGIC = "NAUX-S4-MEASUREMENT-SESSION\t1"
BUNDLE_MAGIC = "NAUX-S4-MEASUREMENT-BUNDLE\t1"
TOOLCHAIN_MAGIC = "NAUX-S4-MEASUREMENT-TOOLCHAINS\t1"
CONTRACT_DOMAIN = b"NAUX:s4-measurement-runner:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-measurement-runner:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-measurement-runner:report:v1\0"
SESSION_DOMAIN = b"NAUX:s4-measurement-runner:session:v1\0"
BINARY_DOMAIN = b"NAUX:s4-measurement-runner:role-binary:v1\0"
TOOLCHAIN_DOMAIN = b"NAUX:s4-measurement-runner:toolchain:v1\0"
BUNDLE_DOMAIN = b"NAUX:s4-measurement-runner:bundle:v1\0"
TOOLCHAIN_RECEIPT_DOMAIN = b"NAUX:s4-measurement-runner:toolchain-receipt:v1\0"
WP6_AUTHORITY_SEAL = "3062a5197fa1fcbe50f60b624b75b2be37c55a0c1193d1eeeffc03e7f03caaf0"
WP6_CONTRACT_SEAL = "64f3ee8279085c35857845ee7c4a4c6d2660695e3c74f43695126c7e5329e123"
WP7A_AUTHORITY_SEAL = "7e10bc03b30b532f05e67c6f6d3ce80d7430125bcae7b9e3824c86cfc233f0bc"
WP7B_NAUX_AUTHORITY_SEAL = "7b9ab600dbb1acc87ff7a4084dc0355b85a69c7cdf967ee072d0f668eb3c0c63"
WP7B_C_AUTHORITY_SEAL = "240bceed62f9ab98b792f2308800df778ce5c35596139349d2a8c03827d63588"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")
RESULT_MAGIC = b"NAUX7B01"
RESULT_BYTES = 56
N = 16_384
REPS = 50
WARMUP_MINIMUM_NS = 100_000_000
SAMPLE_COUNT = 30
MAX_WARMUP_INVOCATIONS = 100_000
PROCESS_TIMEOUT_SECONDS = 30

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-host-protocol", WP6_AUTHORITY_SEAL),
    ("parent-evidence-law", WP7A_AUTHORITY_SEAL),
    ("parent-naux-carrier", WP7B_NAUX_AUTHORITY_SEAL),
    ("parent-c-carrier", WP7B_C_AUTHORITY_SEAL),
    ("runner-status", "measurement-runner-structurally-admitted"),
    ("acquisition-status", "retained-eligible-host-required"),
    ("claim-status", "not-admitted"),
    ("default-mode", "static-no-host-no-clock-no-execution"),
    ("acquire-mode", "explicit-only"),
    ("host-policy", "retained-report-plus-exact-live-reattestation"),
    ("build-policy", "fixed-argv-no-shell"),
    ("artifact-policy", "twelve-exact-role-kernel-artifacts"),
    ("binary-identity", "sha256-ordered-kernel-hash-aggregate"),
    ("toolchain-identity", "sha256-executable-and-version-aggregate"),
    ("warmup-policy", "retain-every-invocation-until-cumulative-100000000ns"),
    ("sample-policy", "role-major-kernel-major-exact30-no-drop-no-retry"),
    ("startup-policy", "nearest-rank-p50-positive-parent-envelope-minus-runtime"),
    ("rss-policy", "maximum-wait4-child-rss-bytes"),
    ("code-size-policy", "sum-four-role-artifact-bytes"),
    ("failure-policy", "atomic-bundle-or-no-bundle"),
    ("result-protocol", "fixed-le56-v1"),
    ("target", "x86_64-unknown-linux-gnu"),
)
CONTRACT_ROLES = (
    ("01", "naux-residual", "1", "native-clean"),
    ("02", "c-generic", "2", "reference-clean"),
    ("03", "c-specialized", "3", "reference-clean"),
)
CONTRACT_KERNELS = tuple(
    (ordinal, name, str(oracle)) for ordinal, name, oracle in wp7a.KERNELS
)
CONTRACT_GATES = (
    ("01", "static-isolation", "required", "no-host-no-clock-no-build-no-execution"),
    ("02", "retained-attestation", "required", "exact-eligible-wp6-report"),
    ("03", "live-reattestation", "required", "exact-facts-fingerprint-commit"),
    ("04", "checkout", "required", "clean-exact-attested-commit"),
    ("05", "toolchains", "required", "resolved-regular-exact-hashes"),
    ("06", "artifacts", "required", "exact-build-and-aggregate-identity"),
    ("07", "warmup", "required", "all-invocations-retained-cumulative-minimum"),
    ("08", "samples", "required", "exact360-no-retry"),
    ("09", "parity", "required", "every-record-exact"),
    ("10", "cost-separation", "required", "compile-specialize-startup-rss-code-size"),
    ("11", "independent-replay", "required", "wp7a-before-publish"),
    ("12", "atomic-publication", "required", "complete-bundle-only"),
)
CONTRACT_CLOSURES = (
    ("01", "measurement-runner-unavailable", "closed", "wp7c-structural-runner"),
)
CONTRACT_BLOCKERS = (
    ("01", "retained-controlled-host-attestation-unavailable"),
    ("02", "raw-measurement-evidence-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP7C"),
    ("authority-id", "s4-controlled-acquisition-runner-v1"),
    ("runner-status", "measurement-runner-structurally-admitted"),
    ("acquisition-status", "retained-eligible-host-required"),
    ("claim-status", "not-admitted"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-measurement-runner.yml",
    "distribution/s4-performance/WP7C-RUNNER.tsv",
    "distribution/s4-performance/WP7C-NONCLAIMS.md",
    "distribution/s4-performance/WP7C-README.md",
    "scripts/s4_measurement_runner.py",
    "scripts/tests/test_s4_measurement_runner_replay.py",
    "scripts/tests/test_s4_measurement_runner_static.py",
)


class RunnerError(RuntimeError):
    """A fail-closed S4-WP7C runner error."""


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


@dataclass(frozen=True)
class RetainedHost:
    raw: bytes
    report_root: str
    fingerprint: str
    facts: tuple[tuple[str, str], ...]

    @property
    def commit(self) -> str:
        return dict(self.facts)["git-commit"]


@dataclass(frozen=True)
class Artifact:
    role: str
    kernel: str
    path: Path
    sha256: str
    size: int


@dataclass(frozen=True)
class ToolIdentity:
    name: str
    executable_path: str
    executable_hash: str
    version_hash: str
    version_hex: str


@dataclass(frozen=True)
class RoleBuild:
    ordinal: str
    name: str
    path_status: str
    binary_hash: str
    toolchain_hash: str
    compile_ns: int
    specialize_ns: int
    artifacts: tuple[Artifact, ...]
    toolchains: tuple[ToolIdentity, ...]

    @property
    def code_size(self) -> int:
        return sum(artifact.size for artifact in self.artifacts)


@dataclass(frozen=True)
class Invocation:
    role: str
    kernel: str
    ordinal: int
    duration_ns: int
    checksum: int
    path_status: str
    envelope_ns: int
    rss_bytes: int

    @property
    def overhead_ns(self) -> int:
        return self.envelope_ns - self.duration_ns


@dataclass(frozen=True)
class AcquisitionData:
    builds: tuple[RoleBuild, ...]
    warmups: tuple[Invocation, ...]
    samples: tuple[Invocation, ...]


@dataclass(frozen=True)
class CarrierResult:
    kernel_ordinal: int
    checksum: int
    outer: int
    inner: int
    owner: int
    duration_ns: int


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(raw: bytes, label: str, maximum: int = 4_000_000) -> list[str]:
    if not raw or len(raw) > maximum or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise RunnerError(f"{label} has invalid extent or encoding")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RunnerError(f"{label} is not UTF-8") from error
    lines = text.splitlines()
    if any(not line for line in lines):
        raise RunnerError(f"{label} contains a blank row")
    return lines


def _regular_bytes(path: Path, label: str, maximum: int = 4_000_000) -> bytes:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise RunnerError(f"cannot read {label}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RunnerError(f"{label} is not a regular file")
    if len(raw) > maximum:
        raise RunnerError(f"{label} exceeds its extent limit")
    return raw


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    raw = _regular_bytes(path, path.name)
    lines = _canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise RunnerError(f"{path.name} magic or shape drifted")
    if any(line.startswith("seal\t") for line in lines[:-1]):
        raise RunnerError(f"{path.name} has a non-terminal seal")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise RunnerError(f"{path.name} seal row is malformed")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if _sha256(domain + body) != fields[1]:
        raise RunnerError(f"{path.name} seal mismatch")
    return lines[1:-1], fields[1]


def _take(lines: list[str], index: int, tag: str, width: int) -> tuple[list[tuple[str, ...]], int]:
    result: list[tuple[str, ...]] = []
    while index < len(lines) and lines[index].startswith(f"{tag}\t"):
        fields = lines[index].split("\t")
        if len(fields) != width:
            raise RunnerError(f"WP7C {tag} row is malformed")
        result.append(tuple(fields[1:]))
        index += 1
    return result, index


def _safe_path(value: str) -> None:
    if not PATH_RE.fullmatch(value):
        raise RunnerError("WP7C bound path token is malformed")
    path = Path(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise RunnerError("WP7C bound path is absolute or traversing")


def parse_contract(path: Path) -> Contract:
    lines, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    index = 0
    metadata, index = _take(lines, index, "meta", 3)
    roles, index = _take(lines, index, "role", 5)
    kernels, index = _take(lines, index, "kernel", 4)
    gates, index = _take(lines, index, "gate", 5)
    closures, index = _take(lines, index, "closure", 5)
    blockers, index = _take(lines, index, "blocker", 3)
    if tuple(metadata) != CONTRACT_METADATA:
        raise RunnerError("WP7C contract metadata drifted")
    if tuple(roles) != CONTRACT_ROLES or tuple(kernels) != CONTRACT_KERNELS:
        raise RunnerError("WP7C role or kernel identity drifted")
    if tuple(gates) != CONTRACT_GATES or tuple(closures) != CONTRACT_CLOSURES:
        raise RunnerError("WP7C gate or closure set drifted")
    if tuple(blockers) != CONTRACT_BLOCKERS or index != len(lines):
        raise RunnerError("WP7C blocker set or extent drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    index = 0
    metadata, index = _take(lines, index, "meta", 3)
    if tuple(metadata) != AUTHORITY_METADATA:
        raise RunnerError("WP7C authority metadata drifted")
    expected_links = (
        ("component", "runner-contract", "distribution/s4-performance/WP7C-RUNNER.tsv", contract_seal),
        ("parent", "host-protocol-authority", "distribution/s4-performance/WP6-AUTHORITY.tsv", WP6_AUTHORITY_SEAL),
        ("parent", "evidence-law-authority", "distribution/s4-performance/WP7A-AUTHORITY.tsv", WP7A_AUTHORITY_SEAL),
        ("parent", "naux-carrier-authority", "distribution/s4-performance/WP7B-AUTHORITY.tsv", WP7B_NAUX_AUTHORITY_SEAL),
        ("parent", "c-carrier-authority", "distribution/s4-performance/C-TIMING-AUTHORITY.tsv", WP7B_C_AUTHORITY_SEAL),
    )
    bindings: list[tuple[str, ...]] = []
    for _expected in expected_links:
        if index >= len(lines):
            raise RunnerError("WP7C authority binding is missing")
        bindings.append(tuple(lines[index].split("\t")))
        index += 1
    if tuple(bindings) != expected_links:
        raise RunnerError("WP7C authority binding drifted")

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
            or fields[5] != "measurement-runner"
        ):
            raise RunnerError("WP7C authority file row is malformed")
        _safe_path(fields[4])
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
        index += 1
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise RunnerError("WP7C authority file inventory drifted")
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        raw = _regular_bytes(path, record.path)
        metadata = path.lstat()
        mode = stat.S_IFREG | stat.S_IMODE(metadata.st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise RunnerError(f"WP7C bound file identity drifted: {record.path}")


def _verify_static_boundary(root: Path) -> None:
    workflow = (root / ".github/workflows/s4-measurement-runner.yml").read_text()
    if "--acquire" in workflow:
        raise RunnerError("WP7C workflow attempts acquisition")
    for token in (
        "scripts/s4_measurement_runner.py",
        "test_s4_measurement_runner_static",
        "test_s4_measurement_runner_replay",
    ):
        if token not in workflow:
            raise RunnerError("WP7C workflow omits a static gate")
    expected = {"WP7C-AUTHORITY.tsv", "WP7C-RUNNER.tsv", "WP7C-NONCLAIMS.md", "WP7C-README.md"}
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP7C-*")
        if path.is_file()
    }
    if actual != expected:
        raise RunnerError("unexpected WP7C distribution artifact")


def _report(contract: Contract, authority: Authority) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"parent-host-protocol\t{WP6_AUTHORITY_SEAL}",
        f"parent-evidence-law\t{WP7A_AUTHORITY_SEAL}",
        f"parent-naux-carrier\t{WP7B_NAUX_AUTHORITY_SEAL}",
        f"parent-c-carrier\t{WP7B_C_AUTHORITY_SEAL}",
        "runner-status\tmeasurement-runner-structurally-admitted",
        "acquisition-status\tretained-eligible-host-required",
        "claim-status\tnot-admitted",
        "mode\tstatic-no-host-no-clock-no-execution",
        "roles\t3",
        "kernels\t4",
        "samples-required\t360",
        "blockers\t2",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve()
    evidence = wp7a.validate(root)
    if evidence.authority.seal != WP7A_AUTHORITY_SEAL:
        raise RunnerError("accepted WP7A evidence authority drifted")
    naux = wp7b_naux.validate(root)
    if naux.authority.seal != WP7B_NAUX_AUTHORITY_SEAL:
        raise RunnerError("accepted WP7B NAUX carrier authority drifted")
    c_carrier = wp7b_c.validate(root)
    if c_carrier.authority.seal != WP7B_C_AUTHORITY_SEAL:
        raise RunnerError("accepted WP7B C carrier authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP7C-RUNNER.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP7C-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_static_boundary(root)
    report, report_root = _report(contract, authority)
    return Admission(contract, authority, report, report_root)


def parse_retained_host(path: Path, admission: Admission) -> RetainedHost:
    raw = _regular_bytes(path, "retained host attestation", 131_072)
    lines = _canonical(raw, "retained host attestation", 131_072)
    if lines[0] != wp7a.wp6.REPORT_MAGIC or not lines[-1].startswith("report-root\t"):
        raise RunnerError("retained host report magic or shape drifted")
    root_fields = lines[-1].split("\t")
    if len(root_fields) != 2 or not HASH_RE.fullmatch(root_fields[1]):
        raise RunnerError("retained host report root is malformed")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if _sha256(wp7a.wp6.REPORT_DOMAIN + body) != root_fields[1]:
        raise RunnerError("retained host report root verification failed")

    fixed = (
        ("contract", WP6_CONTRACT_SEAL),
        ("authority", WP6_AUTHORITY_SEAL),
        ("protocol-status", "controlled-host-protocol-admitted"),
        ("host-status", "eligible-ephemeral-observation"),
        ("claim-status", "not-admitted"),
        ("timing-status", "forbidden"),
        ("mode", "host-observation"),
    )
    cursor = 1
    for key, value in fixed:
        if cursor >= len(lines) - 1 or lines[cursor] != f"{key}\t{value}":
            raise RunnerError("retained host authority or eligibility drifted")
        cursor += 1
    if cursor >= len(lines) - 1:
        raise RunnerError("retained host fingerprint is missing")
    fingerprint_fields = lines[cursor].split("\t")
    if len(fingerprint_fields) != 2 or fingerprint_fields[0] != "fingerprint" or not HASH_RE.fullmatch(fingerprint_fields[1]):
        raise RunnerError("retained host fingerprint is malformed")
    cursor += 1
    facts: list[tuple[str, str]] = []
    for _ordinal, expected_name in wp7a.wp6.CONTRACT_FACTS:
        if cursor >= len(lines) - 1:
            raise RunnerError("retained host facts are truncated")
        fields = lines[cursor].split("\t")
        if len(fields) != 3 or fields[0] != "fact" or fields[1] != expected_name:
            raise RunnerError("retained host fact order drifted")
        wp7a.wp6._safe_fact(fields[2], fields[1])
        facts.append((fields[1], fields[2]))
        cursor += 1
    if cursor >= len(lines) - 1 or lines[cursor] != "refusals\t0":
        raise RunnerError("retained host report is not eligible")
    cursor += 1
    if cursor != len(lines) - 1:
        raise RunnerError("retained host report has refusal or trailing rows")
    fact_body = b"".join(f"fact\t{key}\t{value}\n".encode() for key, value in facts)
    if _sha256(wp7a.wp6.FINGERPRINT_DOMAIN + fact_body) != fingerprint_fields[1]:
        raise RunnerError("retained host fact fingerprint mismatch")
    if not COMMIT_RE.fullmatch(dict(facts).get("git-commit", "")):
        raise RunnerError("retained host commit is malformed")
    return RetainedHost(raw, root_fields[1], fingerprint_fields[1], tuple(facts))


def verify_live_host(root: Path, retained: RetainedHost) -> None:
    observation = wp7a.wp6.observe(root.resolve(), retained.commit)
    if not observation.eligible:
        raise RunnerError("live host is not eligible under WP6")
    if observation.fingerprint != retained.fingerprint or observation.facts != retained.facts:
        raise RunnerError("live host differs from retained attestation")


def decode_carrier_record(raw: bytes, role: str, kernel: str) -> CarrierResult:
    if len(raw) != RESULT_BYTES or raw[:8] != RESULT_MAGIC:
        raise RunnerError("carrier result length or magic drifted")
    kernel_map = {ordinal: (name, oracle) for ordinal, name, oracle in wp7a.KERNELS}
    role_map = {ordinal: (name, int(owner), status) for ordinal, name, owner, status in CONTRACT_ROLES}
    if role not in role_map or kernel not in kernel_map:
        raise RunnerError("unknown carrier role or kernel ordinal")
    values = struct.unpack("<QqQQQQ", raw[8:])
    result = CarrierResult(*values)
    expected_name, oracle = kernel_map[kernel]
    role_name, owner, _status = role_map[role]
    if (
        result.kernel_ordinal != int(kernel)
        or expected_name not in {name for _ordinal, name, _oracle in wp7a.KERNELS}
        or role_name not in {name for _ordinal, name, _owner, _status in CONTRACT_ROLES}
        or result.checksum != oracle
        or result.outer != REPS
        or result.inner != N
        or result.owner != owner
        or result.duration_ns <= 0
    ):
        raise RunnerError("carrier result identity, parity, work, owner, or duration drifted")
    return result


def aggregate_binary_identity(artifacts: tuple[Artifact, ...]) -> str:
    expected_kernels = tuple(ordinal for ordinal, _name, _oracle in wp7a.KERNELS)
    if (
        len(artifacts) != 4
        or tuple(artifact.kernel for artifact in artifacts) != expected_kernels
        or len({artifact.role for artifact in artifacts}) != 1
    ):
        raise RunnerError("role artifact set must contain four ordered kernels")
    for artifact in artifacts:
        raw = _regular_bytes(artifact.path, f"{artifact.role}/{artifact.kernel} artifact")
        if (
            not HASH_RE.fullmatch(artifact.sha256)
            or artifact.size <= 0
            or len(raw) != artifact.size
            or _sha256(raw) != artifact.sha256
            or not os.access(artifact.path, os.X_OK)
        ):
            raise RunnerError("role artifact identity drifted")
    body = b"".join(
        f"artifact\t{artifact.kernel}\t{artifact.sha256}\t{artifact.size}\n".encode()
        for artifact in artifacts
    )
    return _sha256(BINARY_DOMAIN + body)


def aggregate_toolchain_identity(records: tuple[ToolIdentity, ...]) -> str:
    if not records:
        raise RunnerError("toolchain identity is empty")
    body = b""
    for record in records:
        try:
            version = bytes.fromhex(record.version_hex)
        except ValueError as error:
            raise RunnerError("toolchain version receipt is not canonical hex") from error
        if (
            not re.fullmatch(r"[a-z][a-z0-9-]*", record.name)
            or not record.executable_path
            or any(character in record.executable_path for character in "\0\r\n\t")
            or not HASH_RE.fullmatch(record.executable_hash)
            or not HASH_RE.fullmatch(record.version_hash)
            or version.hex() != record.version_hex
            or not version
            or _sha256(version) != record.version_hash
        ):
            raise RunnerError("toolchain identity record is malformed")
        body += (
            f"tool\t{record.name}\t{record.executable_hash}\t{record.version_hash}\n".encode()
        )
    return _sha256(TOOLCHAIN_DOMAIN + body)


def _raw_ns() -> int:
    if not hasattr(time, "CLOCK_MONOTONIC_RAW"):
        raise RunnerError("CLOCK_MONOTONIC_RAW is unavailable")
    value = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    if value <= 0:
        raise RunnerError("CLOCK_MONOTONIC_RAW returned a non-positive value")
    return value


def _resolve_tool(command: str, label: str) -> Path:
    if not command or "\0" in command or "\n" in command:
        raise RunnerError(f"{label} command is malformed")
    located = shutil.which(command)
    if located is None:
        raise RunnerError(f"{label} was not found")
    path = Path(located).resolve(strict=True)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise RunnerError(f"{label} is not a regular executable")
    return path


def _fixed_environment() -> dict[str, str]:
    return {
        "HOME": os.environ.get("HOME", "/nonexistent"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "TZ": "UTC",
    }


def _tool_identity(name: str, path: Path) -> ToolIdentity:
    try:
        completed = subprocess.run(
            [os.fspath(path), "--version"],
            cwd="/",
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_fixed_environment(),
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RunnerError(f"cannot identify {name}") from error
    version = completed.stdout + completed.stderr
    if (
        completed.returncode != 0
        or not version
        or len(version) > 65_536
        or b"\0" in version
        or b"\r" in version
    ):
        raise RunnerError(f"{name} version output is not canonical")
    return ToolIdentity(
        name,
        os.fspath(path),
        _sha256(path.read_bytes()),
        _sha256(version),
        version.hex(),
    )


def _run_build(
    argv: list[str], root: Path, environment: dict[str, str], label: str,
    *, silent: bool,
) -> int:
    start = _raw_ns()
    try:
        completed = subprocess.run(
            argv,
            cwd=root,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RunnerError(f"{label} failed to complete") from error
    elapsed = _raw_ns() - start
    if completed.returncode != 0 or (silent and (completed.stdout or completed.stderr)):
        raise RunnerError(f"{label} failed or emitted unexpected diagnostics")
    if elapsed <= 0:
        raise RunnerError(f"{label} produced a non-positive compile interval")
    return elapsed


def _write_executable(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RunnerError("artifact write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if path.read_bytes() != raw:
        raise RunnerError("artifact readback differs")


def _artifact(role: str, kernel: str, path: Path) -> Artifact:
    raw = _regular_bytes(path, f"{role}/{kernel} artifact")
    if not raw or not os.access(path, os.X_OK):
        raise RunnerError("materialized artifact is empty or non-executable")
    return Artifact(role, kernel, path, _sha256(raw), len(raw))


def _build_naux_role(
    root: Path,
    directory: Path,
    admission: wp7b_naux.Admission,
    cargo: Path,
    rustc: Path,
) -> RoleBuild:
    target = directory / "cargo-target"
    environment = _fixed_environment()
    environment.update({"CARGO_TARGET_DIR": os.fspath(target), "RUSTC": os.fspath(rustc)})
    compile_ns = _run_build(
        [
            os.fspath(cargo), "build", "--locked", "--offline", "--release",
            "-p", "naux", "--example", "naux_s4_residual_timing",
            "--target-dir", os.fspath(target),
        ],
        root,
        environment,
        "NAUX timing emitter build",
        silent=False,
    )
    emitter = target / "release/examples/naux_s4_residual_timing"
    start = _raw_ns()
    _report_bytes, candidate = wp7b_naux.replay(admission, emitter)
    specialize_ns = _raw_ns() - start
    if specialize_ns <= 0:
        raise RunnerError("NAUX specialization interval is non-positive")
    artifacts: list[Artifact] = []
    output = directory / "naux-residual"
    output.mkdir()
    for kernel in candidate.kernels:
        ordinal = f"{kernel.record.ordinal:02}"
        path = output / f"{ordinal}-{kernel.record.name}"
        _write_executable(path, kernel.elf)
        artifacts.append(_artifact("01", ordinal, path))
    artifact_tuple = tuple(artifacts)
    toolchains = (_tool_identity("cargo", cargo), _tool_identity("rustc", rustc))
    return RoleBuild(
        "01",
        "naux-residual",
        "native-clean",
        aggregate_binary_identity(artifact_tuple),
        aggregate_toolchain_identity(toolchains),
        compile_ns,
        specialize_ns,
        artifact_tuple,
        toolchains,
    )


def _build_c_role(
    root: Path,
    directory: Path,
    admission: wp7b_c.Admission,
    compiler: Path,
    *,
    ordinal: str,
    name: str,
    path_status: str,
    role_flags: tuple[str, ...],
) -> RoleBuild:
    output = directory / name
    output.mkdir()
    environment = _fixed_environment()
    artifacts: list[Artifact] = []
    compile_ns = 0
    for record in admission.contract.kernels:
        source = record.derived_path
        stem = f"{record.ordinal:02}-{record.name}"
        assembly = output / f"{stem}.s"
        binary = output / stem
        base = [os.fspath(compiler), *wp7b_c.COMMON_FLAGS, *role_flags, source]
        compile_ns += _run_build(
            [*base, "-S", "-o", os.fspath(assembly)], root, environment,
            f"{name}/{record.name} assembly build", silent=True,
        )
        wp7b_c._audit_assembly(assembly.read_bytes(), f"{name}/{record.name}")
        compile_ns += _run_build(
            [*base, "-o", os.fspath(binary)], root, environment,
            f"{name}/{record.name} binary build", silent=True,
        )
        raw = _regular_bytes(binary, f"{name}/{record.name} binary")
        if len(raw) < 20 or raw[:6] != b"\x7fELF\x02\x01" or raw[18:20] != b"\x3e\x00":
            raise RunnerError("C carrier is not an x86-64 ELF")
        artifacts.append(_artifact(ordinal, f"{record.ordinal:02}", binary))
    artifact_tuple = tuple(artifacts)
    toolchains = (_tool_identity("cc", compiler),)
    return RoleBuild(
        ordinal,
        name,
        path_status,
        aggregate_binary_identity(artifact_tuple),
        aggregate_toolchain_identity(toolchains),
        compile_ns,
        0,
        artifact_tuple,
        toolchains,
    )


def build_roles(
    root: Path, directory: Path, *, cargo_command: str, rustc_command: str,
    cc_command: str,
) -> tuple[RoleBuild, ...]:
    cargo = _resolve_tool(cargo_command, "Cargo")
    rustc = _resolve_tool(rustc_command, "rustc")
    compiler = _resolve_tool(cc_command, "C compiler")
    naux_admission = wp7b_naux.validate(root)
    c_admission = wp7b_c.validate(root)
    return (
        _build_naux_role(root, directory, naux_admission, cargo, rustc),
        _build_c_role(
            root, directory, c_admission, compiler, ordinal="02", name="c-generic",
            path_status="reference-clean", role_flags=(),
        ),
        _build_c_role(
            root, directory, c_admission, compiler, ordinal="03", name="c-specialized",
            path_status="reference-clean", role_flags=wp7b_c.SPECIALIZED_FLAGS,
        ),
    )


def _carrier_argv(artifact: Artifact) -> list[str]:
    argv = [os.fspath(artifact.path)]
    if artifact.role == "02":
        argv.extend((str(N), str(REPS)))
    elif artifact.role not in {"01", "03"}:
        raise RunnerError("unknown artifact role")
    return argv


def execute_carrier(artifact: Artifact) -> tuple[CarrierResult, int, int]:
    # Identity is checked outside the timed parent envelope. The child receives
    # an empty stdin and a minimal environment; no shell participates.
    expected = _artifact(artifact.role, artifact.kernel, artifact.path)
    if expected.sha256 != artifact.sha256 or expected.size != artifact.size:
        raise RunnerError("carrier artifact changed before execution")
    stdout_read, stdout_write = os.pipe2(os.O_CLOEXEC)
    stderr_read, stderr_write = os.pipe2(os.O_CLOEXEC)
    started = _raw_ns()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - behavior is observed through wait4.
        try:
            null = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            os.dup2(null, 0)
            os.dup2(stdout_write, 1)
            os.dup2(stderr_write, 2)
            for descriptor in (null, stdout_read, stdout_write, stderr_read, stderr_write):
                if descriptor > 2:
                    os.close(descriptor)
            os.execve(os.fspath(artifact.path), _carrier_argv(artifact), _fixed_environment())
        except BaseException:
            os._exit(127)

    os.close(stdout_write)
    os.close(stderr_write)
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    status: int | None = None
    usage: resource.struct_rusage | None = None
    timed_out = False
    try:
        for descriptor, name in ((stdout_read, "stdout"), (stderr_read, "stderr")):
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ, name)
        deadline = started + PROCESS_TIMEOUT_SECONDS * 1_000_000_000
        while status is None or selector.get_map():
            for key, _mask in selector.select(0.02):
                try:
                    chunk = os.read(key.fd, 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    os.close(key.fd)
                    continue
                target = stdout if key.data == "stdout" else stderr
                target.extend(chunk)
                if len(stdout) > RESULT_BYTES or len(stderr) > 65_536:
                    raise RunnerError("carrier output exceeds its exact extent")
            if status is None:
                waited_pid, waited_status, waited_usage = os.wait4(pid, os.WNOHANG)
                if waited_pid == pid:
                    status, usage = waited_status, waited_usage
            if status is None and _raw_ns() >= deadline:
                timed_out = True
                os.kill(pid, signal.SIGKILL)
                _waited_pid, status, usage = os.wait4(pid, 0)
        ended = _raw_ns()
    except BaseException:
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.wait4(pid, 0)
            except ChildProcessError:
                pass
        raise
    finally:
        for key in tuple(selector.get_map().values()):
            selector.unregister(key.fd)
            os.close(key.fd)
        selector.close()
    if (
        timed_out
        or status is None
        or usage is None
        or not os.WIFEXITED(status)
        or os.WEXITSTATUS(status) != 0
        or stderr
    ):
        raise RunnerError("carrier timed out, failed, or emitted stderr")
    envelope_ns = ended - started
    rss_bytes = int(usage.ru_maxrss) * 1024
    if envelope_ns <= 0 or rss_bytes <= 0:
        raise RunnerError("carrier envelope or wait4 RSS is non-positive")
    return decode_carrier_record(bytes(stdout), artifact.role, artifact.kernel), envelope_ns, rss_bytes


def collect_invocations(builds: tuple[RoleBuild, ...]) -> AcquisitionData:
    warmups: list[Invocation] = []
    samples: list[Invocation] = []
    for build in builds:
        for artifact in build.artifacts:
            cumulative = 0
            ordinal = 0
            while cumulative < WARMUP_MINIMUM_NS:
                ordinal += 1
                if ordinal > MAX_WARMUP_INVOCATIONS:
                    raise RunnerError("warmup invocation ceiling reached")
                result, envelope, rss = execute_carrier(artifact)
                invocation = Invocation(
                    build.ordinal, artifact.kernel, ordinal, result.duration_ns,
                    result.checksum, build.path_status, envelope, rss,
                )
                if invocation.overhead_ns <= 0:
                    raise RunnerError("warmup parent envelope does not contain runtime")
                warmups.append(invocation)
                cumulative += result.duration_ns
            for sample_ordinal in range(1, SAMPLE_COUNT + 1):
                result, envelope, rss = execute_carrier(artifact)
                invocation = Invocation(
                    build.ordinal, artifact.kernel, sample_ordinal, result.duration_ns,
                    result.checksum, build.path_status, envelope, rss,
                )
                if invocation.overhead_ns <= 0:
                    raise RunnerError("sample parent envelope does not contain runtime")
                samples.append(invocation)
    return AcquisitionData(builds, tuple(warmups), tuple(samples))


def _nearest_rank_p50(values: tuple[int, ...]) -> int:
    if not values or any(value <= 0 for value in values):
        raise RunnerError("startup observations must be positive")
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * 0.5) - 1]


def build_evidence_candidate(
    evidence: wp7a.Admission,
    runner: Admission,
    retained: RetainedHost,
    data: AcquisitionData,
) -> tuple[bytes, bytes]:
    expected_roles = tuple((ordinal, name, status) for ordinal, name, status in wp7a.ROLES)
    observed_roles = tuple((build.ordinal, build.name, build.path_status) for build in data.builds)
    if observed_roles != expected_roles:
        raise RunnerError("acquisition build role order or identity drifted")
    expected_tools = {"01": ("cargo", "rustc"), "02": ("cc",), "03": ("cc",)}
    if any(
        build.binary_hash != aggregate_binary_identity(build.artifacts)
        or build.toolchain_hash != aggregate_toolchain_identity(build.toolchains)
        or tuple(tool.name for tool in build.toolchains) != expected_tools[build.ordinal]
        or build.compile_ns <= 0
        or build.specialize_ns < 0
        or ((build.ordinal == "01") != (build.specialize_ns > 0))
        or build.code_size <= 0
        for build in data.builds
    ):
        raise RunnerError("acquisition build identity or cost drifted")

    expected_pairs = tuple(
        (role[0], kernel[0], kernel[2], role[2])
        for role in wp7a.ROLES
        for kernel in wp7a.KERNELS
    )
    warmup_groups: dict[tuple[str, str], list[Invocation]] = {
        (role, kernel): [] for role, kernel, _oracle, _status in expected_pairs
    }
    for invocation in data.warmups:
        key = (invocation.role, invocation.kernel)
        if key not in warmup_groups:
            raise RunnerError("warmup contains an unknown role/kernel pair")
        wanted = expected_pairs[list(warmup_groups).index(key)]
        if (
            invocation.ordinal != len(warmup_groups[key]) + 1
            or invocation.duration_ns <= 0
            or invocation.checksum != wanted[2]
            or invocation.path_status != wanted[3]
            or invocation.overhead_ns <= 0
            or invocation.rss_bytes <= 0
        ):
            raise RunnerError("warmup order, parity, path, envelope, or RSS drifted")
        warmup_groups[key].append(invocation)
    if any(
        not invocations
        or len(invocations) > MAX_WARMUP_INVOCATIONS
        or sum(invocation.duration_ns for invocation in invocations) < WARMUP_MINIMUM_NS
        for invocations in warmup_groups.values()
    ):
        raise RunnerError("warmup completeness or cumulative minimum drifted")

    sample_groups: dict[tuple[str, str], list[Invocation]] = {
        (role, kernel): [] for role, kernel, _oracle, _status in expected_pairs
    }
    cursor = 0
    for role, kernel, oracle, path_status in expected_pairs:
        for ordinal in range(1, SAMPLE_COUNT + 1):
            if cursor >= len(data.samples):
                raise RunnerError("measured sample set is truncated")
            invocation = data.samples[cursor]
            cursor += 1
            if (
                (invocation.role, invocation.kernel, invocation.ordinal) != (role, kernel, ordinal)
                or invocation.duration_ns <= 0
                or invocation.checksum != oracle
                or invocation.path_status != path_status
                or invocation.overhead_ns <= 0
                or invocation.rss_bytes <= 0
            ):
                raise RunnerError("sample order, parity, path, envelope, or RSS drifted")
            sample_groups[(role, kernel)].append(invocation)
    if cursor != len(data.samples):
        raise RunnerError("measured sample set has trailing rows")

    rows = [
        wp7a.EVIDENCE_MAGIC,
        f"meta\tcontract\t{evidence.contract.seal}",
        f"meta\tevidence-law-authority\t{evidence.authority.seal}",
        f"meta\tcarrier-authority\t{_sha256((WP7B_NAUX_AUTHORITY_SEAL + WP7B_C_AUTHORITY_SEAL).encode())}",
        f"meta\thost-attestation\t{retained.report_root}",
        f"meta\trunner-authority\t{runner.authority.seal}",
        f"meta\tsource-commit\t{retained.commit}",
        "meta\tclock-source\tclock-monotonic-raw",
        "meta\truntime-region\tallocation-initialization-kernel-checksum-validation-teardown",
        "meta\tsample-policy\tordered-complete-no-drop-no-retry",
        f"meta\tsample-count\t{SAMPLE_COUNT}",
        "meta\tclaim-status\tnot-admitted",
    ]
    for build in data.builds:
        rows.append(
            f"role\t{build.ordinal}\t{build.name}\t{build.binary_hash}\t"
            f"{build.toolchain_hash}\t{build.path_status}"
        )
    for build in data.builds:
        role_samples = tuple(invocation for invocation in data.samples if invocation.role == build.ordinal)
        startup = _nearest_rank_p50(tuple(invocation.overhead_ns for invocation in role_samples))
        rss = max(invocation.rss_bytes for invocation in (*data.warmups, *data.samples) if invocation.role == build.ordinal)
        rows.append(
            f"cost\t{build.ordinal}\t{build.compile_ns}\t{build.specialize_ns}\t"
            f"{startup}\t{rss}\t{build.code_size}"
        )
    for role, kernel, oracle, path_status in expected_pairs:
        duration = sum(invocation.duration_ns for invocation in warmup_groups[(role, kernel)])
        rows.append(f"warmup\t{role}\t{kernel}\t{duration}\t{oracle}\t{path_status}")
    for role, kernel, _oracle, _path_status in expected_pairs:
        for invocation in sample_groups[(role, kernel)]:
            rows.append(
                f"sample\t{role}\t{kernel}\t{invocation.ordinal:02}\t{invocation.duration_ns}\t"
                f"{invocation.checksum}\t{invocation.path_status}"
            )
    for role, kernel, _oracle, _path_status in expected_pairs:
        statistic = wp7a.derive_statistic(
            role, kernel,
            tuple(invocation.duration_ns for invocation in sample_groups[(role, kernel)]),
        )
        rows.append(
            f"stat\t{role}\t{kernel}\t{statistic.median_num}\t{statistic.median_den}\t"
            f"{statistic.p95}\t{statistic.cv2_num}\t{statistic.cv2_den}\t"
            f"{'pass' if statistic.stable else 'fail'}"
        )
    body = b"".join(f"{row}\n".encode() for row in rows)
    candidate = body + f"evidence-root\t{_sha256(wp7a.EVIDENCE_DOMAIN + body)}\n".encode()
    carrier_authority = _sha256((WP7B_NAUX_AUTHORITY_SEAL + WP7B_C_AUTHORITY_SEAL).encode())
    wp7a.replay_candidate(
        candidate, evidence,
        carrier_authority=carrier_authority,
        host_attestation=retained.report_root,
        runner_authority=runner.authority.seal,
    )

    session_rows = [
        SESSION_MAGIC,
        f"meta\trunner-authority\t{runner.authority.seal}",
        f"meta\thost-attestation\t{retained.report_root}",
        f"meta\tsource-commit\t{retained.commit}",
        f"meta\tevidence-root\t{candidate.decode().rsplit(chr(9), 1)[1].strip()}",
        "meta\tclaim-status\tnot-admitted",
    ]
    for invocation in data.warmups:
        session_rows.append(
            f"warmup-run\t{invocation.role}\t{invocation.kernel}\t{invocation.ordinal:06}\t"
            f"{invocation.duration_ns}\t{invocation.envelope_ns}\t{invocation.rss_bytes}\t"
            f"{invocation.checksum}\t{invocation.path_status}"
        )
    for invocation in data.samples:
        session_rows.append(
            f"sample-run\t{invocation.role}\t{invocation.kernel}\t{invocation.ordinal:02}\t"
            f"{invocation.duration_ns}\t{invocation.envelope_ns}\t{invocation.rss_bytes}\t"
            f"{invocation.checksum}\t{invocation.path_status}"
        )
    session_body = b"".join(f"{row}\n".encode() for row in session_rows)
    session = session_body + f"session-root\t{_sha256(SESSION_DOMAIN + session_body)}\n".encode()
    return candidate, session


def _write_regular(path: Path, raw: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RunnerError("bundle write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if path.read_bytes() != raw:
        raise RunnerError("bundle readback differs")


def _rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise RunnerError("atomic no-replace publication is unavailable")
    renameat2.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100, os.fsencode(source), -100, os.fsencode(destination), 1
    )
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise RunnerError("output path appeared during atomic publication")
        raise RunnerError(f"atomic bundle publication failed with errno {code}")


def _checked_output(root: Path, output: Path) -> Path:
    output = output.expanduser().absolute()
    if output.name in {"", ".", ".."} or "\0" in os.fspath(output):
        raise RunnerError("output path is malformed")
    output.parent.mkdir(parents=True, exist_ok=True)
    parent = output.parent.resolve(strict=True)
    output = parent / output.name
    resolved_root = root.resolve(strict=True)
    if output == resolved_root or resolved_root in output.parents:
        raise RunnerError("measurement output must be outside the checkout")
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    else:
        raise RunnerError("measurement output already exists")
    return output


def publish_bundle(
    root: Path,
    output: Path,
    runner: Admission,
    retained: RetainedHost,
    data: AcquisitionData,
    evidence: bytes,
    session: bytes,
    host_attestation_path: Path,
) -> str:
    output = _checked_output(root, output)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.stage-", dir=output.parent))
    published = False
    try:
        toolchain_rows = [
            TOOLCHAIN_MAGIC,
            f"meta\trunner-authority\t{runner.authority.seal}",
            f"meta\tsource-commit\t{retained.commit}",
            "meta\tclaim-status\tnot-admitted",
        ]
        for build in data.builds:
            for tool_ordinal, tool in enumerate(build.toolchains, 1):
                toolchain_rows.append(
                    f"tool\t{build.ordinal}\t{tool_ordinal:02}\t{tool.name}\t"
                    f"{tool.executable_path}\t{tool.executable_hash}\t{tool.version_hash}\t"
                    f"{tool.version_hex}"
                )
        toolchain_body = b"".join(f"{row}\n".encode() for row in toolchain_rows)
        toolchain_receipt = toolchain_body + (
            f"toolchain-root\t{_sha256(TOOLCHAIN_RECEIPT_DOMAIN + toolchain_body)}\n"
        ).encode()
        files: list[tuple[str, bytes, int]] = [
            ("HOST-ATTESTATION.tsv", retained.raw, 0o600),
            ("EVIDENCE.tsv", evidence, 0o600),
            ("SESSION.tsv", session, 0o600),
            ("TOOLCHAINS.tsv", toolchain_receipt, 0o600),
        ]
        reproduction = (
            "NAUX-S4-MEASUREMENT-REPRODUCTION\t1\n"
            f"source-commit\t{retained.commit}\n"
            f"runner-authority\t{runner.authority.seal}\n"
            f"host-attestation-root\t{retained.report_root}\n"
            f"original-host-attestation\t{host_attestation_path.resolve(strict=True)}\n"
            "policy\tnew-eligible-attestation-and-new-output-required-for-each-run\n"
        ).encode()
        files.append(("REPRODUCE.tsv", reproduction, 0o600))
        for build in data.builds:
            for artifact in build.artifacts:
                name = next(
                    kernel_name for ordinal, kernel_name, _oracle in wp7a.KERNELS
                    if ordinal == artifact.kernel
                )
                relative = f"artifacts/{build.ordinal}-{build.name}/{artifact.kernel}-{name}"
                files.append((relative, artifact.path.read_bytes(), 0o700))

        manifest_records: list[tuple[str, int, str]] = []
        for relative, raw, mode in files:
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            _write_regular(destination, raw, mode)
            manifest_records.append((relative, len(raw), _sha256(raw)))
        rows = [
            BUNDLE_MAGIC,
            f"meta\trunner-authority\t{runner.authority.seal}",
            f"meta\thost-attestation\t{retained.report_root}",
            f"meta\tsource-commit\t{retained.commit}",
            "meta\tclaim-status\tnot-admitted",
            f"meta\tfile-count\t{len(manifest_records)}",
        ]
        rows.extend(
            f"file\t{relative}\t{size}\t{digest}"
            for relative, size, digest in manifest_records
        )
        body = b"".join(f"{row}\n".encode() for row in rows)
        bundle_root = _sha256(BUNDLE_DOMAIN + body)
        _write_regular(stage / "MANIFEST.tsv", body + f"bundle-root\t{bundle_root}\n".encode())
        directory = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        _rename_noreplace(stage, output)
        published = True
        parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        return bundle_root
    finally:
        if not published:
            shutil.rmtree(stage, ignore_errors=True)


def acquire(
    root: Path,
    host_attestation: Path,
    output: Path,
    *,
    cargo_command: str,
    rustc_command: str,
    cc_command: str,
) -> tuple[bytes, str]:
    root = root.resolve(strict=True)
    runner = validate(root)
    retained = parse_retained_host(host_attestation, runner)
    checked_output = _checked_output(root, output)
    verify_live_host(root, retained)
    with tempfile.TemporaryDirectory(prefix="naux-s4-wp7c-build-") as directory_name:
        builds = build_roles(
            root,
            Path(directory_name),
            cargo_command=cargo_command,
            rustc_command=rustc_command,
            cc_command=cc_command,
        )
        # Build tools are not allowed to mutate the checkout or host envelope.
        verify_live_host(root, retained)
        data = collect_invocations(builds)
        verify_live_host(root, retained)
        evidence_admission = wp7a.validate(root)
        evidence, session = build_evidence_candidate(
            evidence_admission, runner, retained, data
        )
        bundle_root = publish_bundle(
            root,
            checked_output,
            runner,
            retained,
            data,
            evidence,
            session,
            host_attestation,
        )
    rows = (
        REPORT_MAGIC,
        f"contract\t{runner.contract.seal}",
        f"authority\t{runner.authority.seal}",
        f"host-attestation\t{retained.report_root}",
        f"bundle-root\t{bundle_root}",
        "mode\texplicit-controlled-acquisition",
        "samples\t360",
        "claim-status\tnot-admitted",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    return body + f"report-root\t{_sha256(REPORT_DOMAIN + body)}\n".encode(), bundle_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--acquire", action="store_true")
    parser.add_argument("--host-attestation", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--rustc", default="rustc")
    parser.add_argument("--cc", default="cc")
    arguments = parser.parse_args(argv)
    if arguments.acquire and (arguments.host_attestation is None or arguments.output is None):
        parser.error("--acquire requires --host-attestation and --output")
    if not arguments.acquire and (arguments.host_attestation is not None or arguments.output is not None):
        parser.error("host/output arguments require --acquire")
    if not arguments.acquire and any(
        value != default for value, default in (
            (arguments.cargo, "cargo"), (arguments.rustc, "rustc"), (arguments.cc, "cc")
        )
    ):
        parser.error("toolchain arguments require --acquire")
    try:
        if arguments.acquire:
            report, _bundle_root = acquire(
                arguments.root,
                arguments.host_attestation,
                arguments.output,
                cargo_command=arguments.cargo,
                rustc_command=arguments.rustc,
                cc_command=arguments.cc,
            )
            sys.stdout.buffer.write(report)
        else:
            admission = validate(arguments.root)
            sys.stdout.buffer.write(admission.report)
        return 0
    except (
        RunnerError,
        wp7a.EvidenceError,
        wp7a.wp6.HostControlError,
        wp7b_naux.TimingReplayError,
        wp7b_c.CCarrierError,
        OSError,
    ) as error:
        print(f"S4-WP7C validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
