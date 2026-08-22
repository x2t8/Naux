#!/usr/bin/env python3
"""Independently admit and replay the bounded Scope-3 trusted-thesis bundle."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


AUDIT_MAGIC = "NAUX-S3-TRUSTED-THESIS-AUDIT\t1"
TCB_MAGIC = "NAUX-S3-TRUSTED-COMPUTING-BASE\t1"
EXPERIMENT_MAGIC = "NAUX-S3-THESIS-EXPERIMENTS\t1"
AUDIT_DOMAIN = b"NAUX:s3-thesis:audit:v1\0"
TCB_DOMAIN = b"NAUX:s3-thesis:tcb:v1\0"
EXPERIMENT_DOMAIN = b"NAUX:s3-thesis:experiments:v1\0"
REPORT_DOMAIN = b"NAUX:s3-thesis:audit-report:v1\0"
CARRIER_RECORD_DOMAIN = b"NAUX:thesis:surface-native-t1:record:v1\0"
CARRIER_RESULTS_DOMAIN = b"NAUX:thesis:surface-native-t1:results:v1\0"
CARRIER_EVIDENCE_DOMAIN = b"NAUX:thesis:surface-native-t1:evidence:v1\0"
CARRIER_REPORT_DOMAIN = b"NAUX:thesis:surface-native-t1:report:v1\0"
IPC_DOMAIN = b"NAUX:thesis:surface-native-t1:process:ipc:v1\0"
RECEIPT_DOMAIN = b"NAUX:thesis:surface-native-t1:process:receipt:v1\0"
PROCESS_RESULTS_DOMAIN = b"NAUX:thesis:surface-native-t1:process:results:v1\0"
PROCESS_EVIDENCE_DOMAIN = b"NAUX:thesis:surface-native-t1:process:evidence:v1\0"
PROCESS_REPORT_DOMAIN = b"NAUX:thesis:surface-native-t1:process:report:v1\0"

AUDIT_METADATA = (
    ("scope", "S3"),
    ("profile", "trusted-thesis-candidate"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("audit-policy", "1.0.0"),
    ("carrier-schema", "0.1.0"),
    ("carrier-policy", "1.0.0"),
    ("process-schema", "0.1.0"),
    ("process-policy", "1.0.0"),
    ("ipc-schema", "1.0.0"),
    ("cases", "12"),
    ("frame-bytes", "715"),
    ("wp1-commit", "b9a08dfa8504a444c5274ead25fc72d3f67d0ac7"),
    ("wp1-ci-run", "32567172382"),
    ("wp2-commit", "8df287de8e03619df13f93ec775be2d2e86ec0f8"),
    ("wp2-ci-run", "32571897151"),
)
EXPECTED_ROOTS = (
    ("source", "e421ce08fd53c0fe9c0d0be75d202110e96699f89918ed8f8217fdc5416e3652"),
    ("request", "6738f1f7f820ba57a311de4b6e85a4c497f06bd1de91fd46a651c092710e62d4"),
    ("corpus", "150029f8e9c0ae58c7b70fbaa7881fadecd315608f7e36d91d5158678dd73a46"),
    ("core", "d31b07ed7f9ed0bf038bad8cb368f1f53b48ce6adab7d56e18601f68da8c8ac1"),
    ("ssa", "fbbfc3f60ffe6e936b81f2a535d8d43c5bf4318793d9b51803041745f79eb825"),
    ("machine-ir", "93d9c76e64a6f068fde1fb6574888300204b870083d31e1bebdbbbaade56e57e"),
    ("target", "573ca6f8d1f5190dbbd6d2fe15abff4ba4ab1fa58c24ca5e10fddc6bf51178ee"),
    ("target-plan", "b50221274d30505f758a50d546892b2e3cb81b44c60482766cd72cea8e0a3e56"),
    ("target-code", "bea1358d78cda633a106589cd7cc54e25be7209632785be052a62b58c14d46cd"),
    ("carrier-results", "661914e708e3a7b903e82eb9e4681e3f5646dff3baa8113efeb2c6ed50e02791"),
    ("carrier-evidence", "157c8947fd432951ec5cdefca3879992726d4e0b9ade98937ec4f8f66c11efc2"),
    ("carrier-report", "5a770f0a8034656652bf8b978f54207761cc1231711e656f5037e0a6b096815e"),
    ("process-results", "bd835a82c5b1d9cf8f3cd8bbed6517b40132b6d7bf7eab781435882fa661b6e7"),
    ("process-evidence", "6677a52ec741ee3cda867191a2cc5bc8f161414dbf05038c30ecc3363c8b9978"),
    ("process-report", "eef6f4dc99b75fb3504310a014dc77b85e719cb06aac6f81c3f013447a494ca0"),
)
EXPECTED_FILES = (
    ".github/workflows/ci.yml",
    "Cargo.lock",
    "Cargo.toml",
    "distribution/README.md",
    "distribution/s3-thesis/EXPERIMENTS.tsv",
    "distribution/s3-thesis/LIMITATIONS.md",
    "distribution/s3-thesis/TCB.tsv",
    "naux-lang/Cargo.toml",
    "naux-lang/src/bin/naux_surface_native_t1.rs",
    "naux-lang/src/bin/naux_surface_native_t1_process.rs",
    "naux-lang/src/bin/naux_surface_native_t1_worker.rs",
    "naux-lang/src/thesis_surface_native.rs",
    "naux-lang/src/thesis_surface_native_process.rs",
    "scripts/s3_thesis_audit.py",
    "scripts/tests/test_s3_thesis_audit.py",
)
EXPECTED_TCB_KEYS = (
    ("01", "build-seed", "rustc", "1.96.0", "required"),
    ("02", "build-seed", "cargo", "1.96.0", "required"),
    ("03", "build-seed", "rust-standard-library", "1.96.0", "required"),
    ("04", "build-seed", "rust-llvm-backend", "22.1.2", "indirect-required"),
    ("05", "build-seed", "egg", "0.10.0", "required"),
    ("06", "runtime-tcb", "naux-surface-native-t1", "wp1", "required"),
    ("07", "runtime-tcb", "naux-surface-native-t1-worker", "wp2", "required"),
    ("08", "runtime-tcb", "naux-surface-native-t1-process", "wp2", "required"),
    ("09", "host-abi", "linux-x86-64", "wp1-wp2", "required"),
    ("10", "host-abi", "x86-64-sse2-mxcsr", "wp1-wp2", "required"),
    ("11", "host-abi", "mmap-mprotect-munmap", "wp1-wp2", "required"),
    ("12", "host-abi", "process-lifecycle-and-pipes", "wp2", "required"),
    ("13", "host-abi", "dynamic-loader-libc-libgcc", "build-host", "required-if-linked"),
    ("14", "evaluator", "python-standard-library", "3.11+", "required"),
    ("15", "evaluator", "github-actions-ubuntu", "pinned-actions", "required-for-public-ci"),
    ("16", "optional-tool", "git", "unspecified", "optional"),
    ("17", "optional-tool", "gh", "unspecified", "optional"),
)
EXPECTED_TCB_DESCRIPTIONS = (
    "Current compiler seed; not part of the claimed future self-origin path.",
    "Current workspace and dependency builder.",
    "Linked Rust seed support used by the three reviewed evidence binaries.",
    "Rustc seed backend debt; NAUX does not directly call LLVM as its language backend.",
    "Current equality-saturation source dependency and explicit seed debt.",
    "Produces the fixed in-process six-way carrier report.",
    "Executes exactly one canonical ordinal and emits one fixed binary frame.",
    "Reconstructs the carrier and admits fresh-child observations.",
    "Only admitted operating-system and architecture pair for this evidence.",
    "Floating-point ABI and control-state assumptions used by native execution.",
    "Host memory mapping primitives used by the W-to-X lifecycle.",
    "Fresh child creation, bounded collection, exit status, stdout, and stderr.",
    "Exact produced-binary dependencies remain build-host facts and are not attested here.",
    "Independent parser, hash reconstruction, fixed-argv replay, and audit report.",
    "Public evaluator environment; not the compiler or runtime semantic authority.",
    "Repository inspection only; never required by static or binary replay admission.",
    "Public CI observation only; never required by static or binary replay admission.",
)
EXPECTED_EXPERIMENT_KEYS = (
    ("01", "positive", "wp1-six-way-semantic-agreement", "admitted"),
    ("02", "positive", "wp1-regenerative-evidence", "admitted"),
    ("03", "positive", "wp2-fresh-process-isolation", "admitted"),
    ("04", "positive", "wp3-static-bundle-admission", "required"),
    ("05", "positive", "wp3-fixed-argv-replay", "required"),
    ("06", "positive", "wp3-deterministic-double-replay", "required"),
    ("07", "positive", "wp3-public-ci", "required"),
    ("08", "negative", "carrier-reseal-mutation", "admitted"),
    ("09", "negative", "process-abnormal-child", "admitted"),
    ("10", "negative", "process-frame-structure", "admitted"),
    ("11", "negative", "process-resealed-frame", "admitted"),
    ("12", "negative", "wp3-manifest-mutation", "required"),
    ("13", "negative", "wp3-stale-root-mutation", "required"),
    ("14", "negative", "wp3-command-injection-mutation", "required"),
    ("15", "unsupported", "unsupported-host", "explicit"),
    ("16", "nonclaim", "performance-leadership", "not-claimed"),
    ("17", "nonclaim", "sandbox-or-executable-attestation", "not-claimed"),
    ("18", "nonclaim", "general-language-correctness", "not-claimed"),
    ("19", "nonclaim", "self-origin-p2-p3", "not-claimed"),
)
EXPECTED_EXPERIMENT_DESCRIPTIONS = (
    "Surface Core SSA Machine-IR target-plan and native agree on the fixed twelve-case corpus.",
    "Canonical reconstruction rejects locally resealed observation order and cardinality drift.",
    "One fresh child per ordinal emits an exact bounded binary frame for parent reconstruction.",
    "Sealed audit TCB experiment and file inventories must pass without building Rust.",
    "The evaluator must replay the three reviewed binaries without a shell.",
    "Text reports and all twelve worker frames must be byte-identical across two runs.",
    "The final tracked commit must pass the public pinned-toolchain CI run.",
    "Coherently resealed value provenance order and cardinality mutations are rejected.",
    "Timeout abort nonzero exit missing output diagnostics overflow and descendant pipe retention are rejected.",
    "Malformed oversized truncated trailing and double frames are rejected.",
    "Wrong ordinal observation identity and W-to-X mapping mutations remain rejected after resealing.",
    "Schema order count hash path mode seal and inventory mutations must fail closed.",
    "A correctly resealed bundle with a non-admitted semantic root must still be rejected.",
    "Unknown or command-shaped step identifiers must be rejected as data.",
    "The carrier is refused outside Linux x86-64 rather than silently weakened.",
    "No C C++ Rust or general performance comparison is admitted by this bundle.",
    "Fresh-process isolation does not attest executable bytes dependencies identity or sandbox strength.",
    "The fixed T1 corpus is not a proof of all NAUX programs or compiler passes.",
    "Seed-debt removal Nauxogenesis Futamura P2 and Futamura P3 remain future work.",
)
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
STEP_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")


class AuditError(RuntimeError):
    """A fail-closed Scope-3 audit error."""


@dataclass(frozen=True)
class FileRecord:
    mode: int
    size: int
    sha256: str
    path: str


@dataclass(frozen=True)
class AuditBundle:
    metadata: tuple[tuple[str, str], ...]
    roots: tuple[tuple[str, str], ...]
    tcb_seal: str
    experiments_seal: str
    files: tuple[FileRecord, ...]
    seal: str


@dataclass(frozen=True)
class Scalar:
    tag: int
    payload: int


@dataclass(frozen=True)
class CarrierCase:
    ordinal: int
    name: str
    input_hash: str
    values: tuple[Scalar, ...]
    record_hash: str


@dataclass(frozen=True)
class CarrierReport:
    cases: tuple[CarrierCase, ...]
    report_hash: str


@dataclass(frozen=True)
class ProcessCase:
    ordinal: int
    input_hash: str
    carrier_record_hash: str
    frame_hash: str
    receipt_hash: str


@dataclass(frozen=True)
class ProcessReport:
    cases: tuple[ProcessCase, ...]
    report_hash: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_bytes(value: str, field: str) -> bytes:
    if not HASH_RE.fullmatch(value):
        raise AuditError(f"invalid SHA-256 for {field}")
    return bytes.fromhex(value)


def _read_lines(path: Path, *, limit: int = 1_000_000) -> tuple[bytes, list[str]]:
    raw = path.read_bytes()
    if len(raw) > limit:
        raise AuditError(f"file exceeds audit size limit: {path}")
    if not raw.endswith(b"\n"):
        raise AuditError(f"file must end with one LF: {path}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AuditError(f"file must be UTF-8: {path}") from error
    if "\r" in text or "\x00" in text:
        raise AuditError(f"file must use canonical LF text: {path}")
    lines = text.splitlines()
    if any(not line for line in lines):
        raise AuditError(f"blank lines are not canonical: {path}")
    return raw, lines


def _sealed_lines(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    _raw, lines = _read_lines(path)
    if not lines or lines[0] != magic:
        raise AuditError(f"unsupported schema: {path}")
    if len(lines) < 2:
        raise AuditError(f"missing seal: {path}")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or fields[0] != "seal" or not HASH_RE.fullmatch(fields[1]):
        raise AuditError(f"malformed final seal: {path}")
    body = "".join(f"{line}\n" for line in lines[:-1]).encode()
    if _sha256(domain + body) != fields[1]:
        raise AuditError(f"seal mismatch: {path}")
    return lines[:-1], fields[1]


def parse_tcb(path: Path) -> str:
    lines, seal = _sealed_lines(path, TCB_MAGIC, TCB_DOMAIN)
    expected_header = ["scope\tS3", "profile\ttrusted-thesis-candidate", "target\tx86_64-unknown-linux-gnu", "policy\t1.0.0", "entries\t17"]
    if lines[1:6] != expected_header or len(lines) != 6 + len(EXPECTED_TCB_KEYS):
        raise AuditError("TCB header or count drift")
    keys = []
    descriptions = []
    classes = set()
    for line in lines[6:]:
        fields = line.split("\t")
        if len(fields) != 7 or fields[0] != "entry" or not fields[6].strip():
            raise AuditError("malformed TCB entry")
        keys.append(tuple(fields[1:6]))
        descriptions.append(fields[6])
        classes.add(fields[2])
    if tuple(keys) != EXPECTED_TCB_KEYS:
        raise AuditError("TCB identity, order, or status drift")
    if tuple(descriptions) != EXPECTED_TCB_DESCRIPTIONS:
        raise AuditError("TCB description drift")
    if classes != {"build-seed", "runtime-tcb", "host-abi", "evaluator", "optional-tool"}:
        raise AuditError("TCB classes are incomplete")
    return seal


def parse_experiments(path: Path) -> str:
    lines, seal = _sealed_lines(path, EXPERIMENT_MAGIC, EXPERIMENT_DOMAIN)
    expected_header = ["scope\tS3", "profile\ttrusted-thesis-candidate", "policy\t1.0.0", "steps\t19"]
    if lines[1:5] != expected_header or len(lines) != 5 + len(EXPECTED_EXPERIMENT_KEYS):
        raise AuditError("experiment header or count drift")
    keys = []
    descriptions = []
    for line in lines[5:]:
        fields = line.split("\t")
        if len(fields) != 6 or fields[0] != "step" or not fields[5].strip():
            raise AuditError("malformed experiment step")
        if not STEP_RE.fullmatch(fields[3]):
            raise AuditError("experiment step identifier is not data-only")
        keys.append(tuple(fields[1:5]))
        descriptions.append(fields[5])
    if tuple(keys) != EXPECTED_EXPERIMENT_KEYS:
        raise AuditError("experiment identity, order, kind, or status drift")
    if tuple(descriptions) != EXPECTED_EXPERIMENT_DESCRIPTIONS:
        raise AuditError("experiment description drift")
    return seal


def parse_audit(path: Path) -> AuditBundle:
    lines, seal = _sealed_lines(path, AUDIT_MAGIC, AUDIT_DOMAIN)
    cursor = 1
    metadata = []
    for expected in AUDIT_METADATA:
        if cursor >= len(lines):
            raise AuditError("truncated audit metadata")
        fields = lines[cursor].split("\t")
        if len(fields) != 2 or tuple(fields) != expected:
            raise AuditError(f"audit metadata drift at {expected[0]}")
        metadata.append(tuple(fields))
        cursor += 1
    roots = []
    for expected_name, expected_hash in EXPECTED_ROOTS:
        if cursor >= len(lines):
            raise AuditError("truncated audit roots")
        fields = lines[cursor].split("\t")
        if len(fields) != 3 or fields != ["root", expected_name, expected_hash]:
            raise AuditError(f"admitted semantic root drift at {expected_name}")
        _hash_bytes(fields[2], expected_name)
        roots.append((fields[1], fields[2]))
        cursor += 1
    seals = []
    for expected_key in ("tcb-seal", "experiments-seal"):
        if cursor >= len(lines):
            raise AuditError("truncated component seals")
        fields = lines[cursor].split("\t")
        if len(fields) != 2 or fields[0] != expected_key:
            raise AuditError(f"missing {expected_key}")
        _hash_bytes(fields[1], expected_key)
        seals.append(fields[1])
        cursor += 1
    if cursor >= len(lines):
        raise AuditError("missing audit file count")
    count_fields = lines[cursor].split("\t")
    if len(count_fields) != 2 or count_fields[0] != "files":
        raise AuditError("missing audit file count")
    try:
        count = int(count_fields[1])
    except ValueError as error:
        raise AuditError("audit file count is not an integer") from error
    if str(count) != count_fields[1] or count != len(EXPECTED_FILES):
        raise AuditError("audit file count drift")
    cursor += 1
    records = []
    for _ in range(count):
        if cursor >= len(lines):
            raise AuditError("truncated audit file inventory")
        fields = lines[cursor].split("\t")
        if len(fields) != 5 or fields[0] != "file":
            raise AuditError("malformed audit file record")
        try:
            mode = int(fields[1], 8)
            size = int(fields[2])
        except ValueError as error:
            raise AuditError("invalid audit file mode or size") from error
        if (
            fields[1] != f"{mode:04o}"
            or fields[2] != str(size)
            or mode not in (0o644, 0o755)
            or size < 0
        ):
            raise AuditError("audit file mode or size is outside policy")
        _hash_bytes(fields[3], "file")
        candidate = Path(fields[4])
        if candidate.is_absolute() or ".." in candidate.parts or fields[4] != candidate.as_posix():
            raise AuditError("audit file path is not canonical and relative")
        records.append(FileRecord(mode, size, fields[3], fields[4]))
        cursor += 1
    if cursor != len(lines):
        raise AuditError("unexpected audit trailing record")
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise AuditError("audit inventory identity or byte order drift")
    return AuditBundle(tuple(metadata), tuple(roots), seals[0], seals[1], tuple(records), seal)


def verify_bundle(repo_root: Path, audit_path: Path) -> AuditBundle:
    bundle = parse_audit(audit_path)
    tcb = parse_tcb(repo_root / "distribution/s3-thesis/TCB.tsv")
    experiments = parse_experiments(repo_root / "distribution/s3-thesis/EXPERIMENTS.tsv")
    if tcb != bundle.tcb_seal or experiments != bundle.experiments_seal:
        raise AuditError("component seal is not bound by AUDIT.tsv")
    for record in bundle.files:
        path = repo_root / record.path
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise AuditError(f"audit member is not a regular file: {record.path}")
        if stat.S_IMODE(info.st_mode) != record.mode:
            raise AuditError(f"audit member mode drift: {record.path}")
        data = path.read_bytes()
        if len(data) != record.size or _sha256(data) != record.sha256:
            raise AuditError(f"audit member content drift: {record.path}")
    return bundle


def _version(value: str) -> bytes:
    try:
        parts = tuple(int(part) for part in value.split("."))
    except ValueError as error:
        raise AuditError("invalid semantic version") from error
    if len(parts) != 3 or any(part < 0 or part > 65535 for part in parts):
        raise AuditError("invalid semantic version")
    return struct.pack(">HHH", *parts)


def _parse_scalar(text: str) -> Scalar:
    if text == "bool:false":
        return Scalar(0, 0)
    if text == "bool:true":
        return Scalar(0, 1)
    if text.startswith("i64:"):
        try:
            value = int(text[4:])
        except ValueError as error:
            raise AuditError("invalid i64 scalar") from error
        if not -(1 << 63) <= value < (1 << 63) or str(value) != text[4:]:
            raise AuditError("noncanonical i64 scalar")
        return Scalar(1, value)
    if re.fullmatch(r"f64:0x[0-9a-f]{16}", text):
        return Scalar(2, int(text[6:], 16))
    raise AuditError("invalid normalized scalar")


def _scalar_bytes(value: Scalar, *, fixed: bool = False) -> bytes:
    if value.tag == 0:
        payload = bytes((value.payload,))
        return bytes((0,)) + payload + (b"\0" * 7 if fixed else b"")
    if value.tag == 1:
        return bytes((1,)) + struct.pack(">q", value.payload)
    if value.tag == 2:
        return bytes((2,)) + struct.pack(">Q", value.payload)
    raise AuditError("unknown normalized scalar tag")


def _strict_output(completed: subprocess.CompletedProcess[bytes], label: str, limit: int) -> bytes:
    if completed.returncode != 0:
        raise AuditError(f"{label} exited with {completed.returncode}")
    if completed.stderr:
        raise AuditError(f"{label} emitted stderr")
    if not completed.stdout or len(completed.stdout) > limit:
        raise AuditError(f"{label} output size is outside policy")
    return completed.stdout


def _reviewed_executable(path: Path, label: str) -> Path:
    path = path.resolve(strict=True)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        raise AuditError(f"{label} is not a reviewed regular executable")
    return path


def _run(argv: list[str], label: str, limit: int, timeout: float = 45.0) -> bytes:
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired as error:
        raise AuditError(f"{label} exceeded replay timeout") from error
    return _strict_output(completed, label, limit)


def _report_lines(raw: bytes, label: str) -> list[str]:
    if not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise AuditError(f"{label} is not canonical LF text")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise AuditError(f"{label} is not UTF-8") from error
    if any(not line for line in lines):
        raise AuditError(f"{label} contains blank lines")
    return lines


def parse_carrier_report(raw: bytes, roots: dict[str, str]) -> CarrierReport:
    lines = _report_lines(raw, "carrier report")
    cursor = 0
    if lines[cursor] != "NAUX-SURFACE-NATIVE-T1":
        raise AuditError("carrier report magic drift")
    cursor += 1
    if lines[cursor:cursor + 2] != ["schema\t0.1.0", "policy\t1.0.0"]:
        raise AuditError("carrier schema or policy drift")
    cursor += 2
    report_root_names = ("source", "request", "corpus", "core", "ssa", "machine-ir", "target", "target-plan", "target-code", "carrier-results", "carrier-evidence")
    for report_name in report_root_names:
        fields = lines[cursor].split("\t")
        wire_name = report_name.removeprefix("carrier-")
        if fields != ["root", wire_name, roots[report_name]]:
            raise AuditError(f"carrier report root drift at {report_name}")
        cursor += 1
    if lines[cursor] != "columns\tcase\tordinal\tname\tinput\tsurface\tcore\tssa\tmachine-ir\ttarget-plan\tnative\trecord":
        raise AuditError("carrier report columns drift")
    cursor += 1
    cases = []
    for ordinal in range(12):
        fields = lines[cursor].split("\t")
        if len(fields) != 11 or fields[0] != "case" or fields[1] != str(ordinal):
            raise AuditError("carrier case order or shape drift")
        if not STEP_RE.fullmatch(fields[2]):
            raise AuditError("carrier case name is not canonical")
        input_hash = fields[3]
        _hash_bytes(input_hash, "carrier input")
        values = tuple(_parse_scalar(value) for value in fields[4:10])
        record_hash = fields[10]
        _hash_bytes(record_hash, "carrier record")
        record_body = CARRIER_RECORD_DOMAIN + struct.pack(">I", ordinal) + bytes.fromhex(input_hash)
        record_body += b"".join(_scalar_bytes(value) for value in values)
        if _sha256(record_body) != record_hash:
            raise AuditError(f"carrier record hash mismatch at case {ordinal}")
        cases.append(CarrierCase(ordinal, fields[2], input_hash, values, record_hash))
        cursor += 1
    if lines[cursor] != "records\t12":
        raise AuditError("carrier record cardinality drift")
    rendered_end = cursor + 1
    cursor += 1
    if cursor + 2 != len(lines) or not lines[cursor].startswith("report\t") or lines[cursor + 1] != "verification\tregenerated":
        raise AuditError("carrier report trailer drift")
    report_hash = lines[cursor].split("\t")[1]
    _hash_bytes(report_hash, "carrier report")
    results = _sha256(CARRIER_RESULTS_DOMAIN + struct.pack(">I", 12) + b"".join(bytes.fromhex(case.record_hash) for case in cases))
    if results != roots["carrier-results"]:
        raise AuditError("carrier results reconstruction mismatch")
    evidence_body = CARRIER_EVIDENCE_DOMAIN + _version("0.1.0") + _version("1.0.0")
    evidence_body += b"".join(bytes.fromhex(roots[name]) for name in ("source", "request", "corpus", "core", "ssa", "machine-ir", "target", "target-plan", "target-code", "carrier-results"))
    evidence_body += struct.pack(">I", 12)
    if _sha256(evidence_body) != roots["carrier-evidence"]:
        raise AuditError("carrier evidence reconstruction mismatch")
    rendered = "".join(f"{line}\n" for line in lines[:rendered_end]).encode()
    if _sha256(CARRIER_REPORT_DOMAIN + rendered) != report_hash or report_hash != roots["carrier-report"]:
        raise AuditError("carrier report seal mismatch")
    return CarrierReport(tuple(cases), report_hash)


def parse_process_report(raw: bytes, roots: dict[str, str], carrier: CarrierReport) -> ProcessReport:
    lines = _report_lines(raw, "process report")
    cursor = 0
    expected_prefix = ["NAUX-SURFACE-NATIVE-T1-PROCESS", "schema\t0.1.0", "process-policy\t1.0.0", "ipc\t1.0.0", "frame-bytes\t715"]
    if lines[:5] != expected_prefix:
        raise AuditError("process report header drift")
    cursor = 5
    for wire_name, root_name in (("source", "source"), ("corpus", "corpus"), ("carrier-results", "carrier-results"), ("process-results", "process-results"), ("process-evidence", "process-evidence")):
        if lines[cursor].split("\t") != ["root", wire_name, roots[root_name]]:
            raise AuditError(f"process report root drift at {wire_name}")
        cursor += 1
    if lines[cursor] != "columns\tordinal\tinput\tcarrier-record\tipc-frame\treceipt":
        raise AuditError("process report columns drift")
    cursor += 1
    cases = []
    for ordinal in range(12):
        fields = lines[cursor].split("\t")
        if len(fields) != 6 or fields[:2] != ["case", str(ordinal)]:
            raise AuditError("process case order or shape drift")
        for field in fields[2:]:
            _hash_bytes(field, "process case")
        carrier_case = carrier.cases[ordinal]
        if fields[2] != carrier_case.input_hash or fields[3] != carrier_case.record_hash:
            raise AuditError("process receipt does not bind carrier case")
        receipt_body = RECEIPT_DOMAIN + _version("0.1.0") + _version("1.0.0") + _version("1.0.0")
        receipt_body += struct.pack(">I", ordinal) + b"".join(bytes.fromhex(value) for value in fields[2:5])
        if _sha256(receipt_body) != fields[5]:
            raise AuditError(f"process receipt reconstruction mismatch at case {ordinal}")
        cases.append(ProcessCase(ordinal, *fields[2:]))
        cursor += 1
    if lines[cursor] != "records\t12":
        raise AuditError("process record cardinality drift")
    rendered_end = cursor + 1
    cursor += 1
    if cursor + 2 != len(lines) or not lines[cursor].startswith("report\t") or lines[cursor + 1] != "verification\tregenerated-fresh-children":
        raise AuditError("process report trailer drift")
    report_hash = lines[cursor].split("\t")[1]
    _hash_bytes(report_hash, "process report")
    results_body = PROCESS_RESULTS_DOMAIN + bytes.fromhex(roots["carrier-results"]) + struct.pack(">I", 12)
    results_body += b"".join(bytes.fromhex(case.receipt_hash) for case in cases)
    if _sha256(results_body) != roots["process-results"]:
        raise AuditError("process results reconstruction mismatch")
    evidence_body = PROCESS_EVIDENCE_DOMAIN + _version("0.1.0") + _version("1.0.0") + _version("1.0.0")
    evidence_body += b"".join(bytes.fromhex(roots[name]) for name in ("source", "request", "corpus", "core", "ssa", "machine-ir", "target", "target-plan", "target-code", "carrier-results", "carrier-evidence", "process-results"))
    evidence_body += struct.pack(">I", 12)
    if _sha256(evidence_body) != roots["process-evidence"]:
        raise AuditError("process evidence reconstruction mismatch")
    rendered = "".join(f"{line}\n" for line in lines[:rendered_end]).encode()
    if _sha256(PROCESS_REPORT_DOMAIN + rendered) != report_hash or report_hash != roots["process-report"]:
        raise AuditError("process report seal mismatch")
    return ProcessReport(tuple(cases), report_hash)


class _Cursor:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, size: int, field: str) -> bytes:
        end = self.pos + size
        if end > len(self.data):
            raise AuditError(f"worker frame truncated at {field}")
        value = self.data[self.pos:end]
        self.pos = end
        return value

    def u8(self, field: str) -> int:
        return self.take(1, field)[0]

    def u32(self, field: str) -> int:
        return struct.unpack(">I", self.take(4, field))[0]

    def digest(self, field: str) -> str:
        return self.take(32, field).hex()

    def scalar(self, field: str) -> Scalar:
        tag = self.u8(field)
        payload = self.take(8, field)
        if tag == 0:
            if payload[0] > 1 or any(payload[1:]):
                raise AuditError(f"noncanonical boolean in {field}")
            return Scalar(0, payload[0])
        if tag == 1:
            return Scalar(1, struct.unpack(">q", payload)[0])
        if tag == 2:
            return Scalar(2, struct.unpack(">Q", payload)[0])
        raise AuditError(f"unknown scalar tag in {field}")


def verify_worker_frame(raw: bytes, ordinal: int, roots: dict[str, str], carrier: CarrierReport, process: ProcessReport) -> None:
    if len(raw) != 715:
        raise AuditError(f"worker frame {ordinal} has {len(raw)} bytes instead of 715")
    cursor = _Cursor(raw)
    if cursor.take(len(IPC_DOMAIN), "domain") != IPC_DOMAIN:
        raise AuditError("worker IPC domain drift")
    if cursor.take(18, "versions") != _version("0.1.0") + _version("1.0.0") + _version("1.0.0"):
        raise AuditError("worker IPC version drift")
    if cursor.u32("ordinal") != ordinal:
        raise AuditError("worker ordinal drift")
    for root_name in ("source", "request", "corpus", "core", "ssa", "machine-ir", "target", "target-plan", "target-code"):
        if cursor.digest(root_name) != roots[root_name]:
            raise AuditError(f"worker root drift at {root_name}")
    expected = carrier.cases[ordinal]
    if cursor.digest("input") != expected.input_hash:
        raise AuditError("worker input binding drift")
    values = tuple(cursor.scalar(f"value-{index}") for index in range(6))
    if values != expected.values:
        raise AuditError("worker semantic observation drift")
    if cursor.digest("carrier-record") != expected.record_hash:
        raise AuditError("worker carrier-record drift")
    native_roots = ("target", "target-plan", "machine-ir", "target-code", "target-code", "target-code")
    for index, root_name in enumerate(native_roots):
        if cursor.digest(f"native-hash-{index}") != roots[root_name]:
            raise AuditError(f"worker native identity drift at {index}")
    if cursor.take(4, "mapping-trace") != bytes((0, 1, 2, 0)):
        raise AuditError("worker W-to-X mapping trace drift")
    if cursor.u8("input-lanes") != 5:
        raise AuditError("worker input-lane count drift")
    before = cursor.u32("mxcsr-before")
    after = cursor.u32("mxcsr-after")
    if before & ~0x3F != 0x1F80 or after != before:
        raise AuditError("worker MXCSR control or restoration drift")
    if cursor.u8("fallback") != 0 or cursor.u32("effects") != 0:
        raise AuditError("worker fallback or observable effect")
    frame_hash = cursor.digest("frame-hash")
    if cursor.pos != len(raw) or _sha256(raw[:-32]) != frame_hash:
        raise AuditError("worker frame seal mismatch")
    if frame_hash != process.cases[ordinal].frame_hash:
        raise AuditError("worker frame does not bind process receipt")


def replay(bundle: AuditBundle, t1_path: Path, worker_path: Path, process_path: Path) -> tuple[CarrierReport, ProcessReport]:
    roots = dict(bundle.roots)
    t1 = _reviewed_executable(t1_path, "T1 binary")
    worker = _reviewed_executable(worker_path, "worker binary")
    process = _reviewed_executable(process_path, "process binary")
    carrier_raw = _run([os.fspath(t1)], "T1 binary", 131_072)
    if _run([os.fspath(t1)], "T1 binary replay", 131_072) != carrier_raw:
        raise AuditError("carrier report is not byte-deterministic")
    carrier = parse_carrier_report(carrier_raw, roots)
    process_raw = _run([os.fspath(process), os.fspath(worker)], "process binary", 131_072, 90.0)
    if _run([os.fspath(process), os.fspath(worker)], "process binary replay", 131_072, 90.0) != process_raw:
        raise AuditError("process report is not byte-deterministic")
    process_report = parse_process_report(process_raw, roots, carrier)
    for ordinal in range(12):
        frame = _run([os.fspath(worker), str(ordinal)], f"worker case {ordinal}", 715)
        if _run([os.fspath(worker), str(ordinal)], f"worker replay {ordinal}", 715) != frame:
            raise AuditError(f"worker frame {ordinal} is not byte-deterministic")
        verify_worker_frame(frame, ordinal, roots, carrier, process_report)
    return carrier, process_report


def render_audit_report(bundle: AuditBundle, *, replayed: bool) -> str:
    mode = "fixed-argv-replay" if replayed else "static-only"
    lines = [
        "NAUX-S3-TRUSTED-THESIS-AUDIT-REPORT",
        "schema\t1.0.0",
        f"mode\t{mode}",
        f"bundle\t{bundle.seal}",
        f"tcb\t{bundle.tcb_seal}",
        f"experiments\t{bundle.experiments_seal}",
        f"files-verified\t{len(bundle.files)}",
        f"semantic-roots\t{len(bundle.roots)}",
        f"tcb-entries\t{len(EXPECTED_TCB_KEYS)}",
        f"experiment-steps\t{len(EXPECTED_EXPERIMENT_KEYS)}",
        f"carrier-runs\t{2 if replayed else 0}",
        f"process-runs\t{2 if replayed else 0}",
        f"worker-frames\t{24 if replayed else 0}",
        f"carrier-results\t{dict(bundle.roots)['carrier-results']}",
        f"process-results\t{dict(bundle.roots)['process-results']}",
        "performance-leadership\tnot-claimed",
        "sandbox\tnot-claimed",
        "standalone-self-origin\tnot-claimed",
    ]
    prefix = "".join(f"{line}\n" for line in lines)
    audit_root = _sha256(REPORT_DOMAIN + prefix.encode())
    return prefix + f"audit\t{audit_root}\nverification\t{'replayed' if replayed else 'static-bound'}\n"


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, default=repo_root / "distribution/s3-thesis/AUDIT.tsv")
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--t1-binary", type=Path)
    parser.add_argument("--worker-binary", type=Path)
    parser.add_argument("--process-binary", type=Path)
    args = parser.parse_args(argv)
    binaries = (args.t1_binary, args.worker_binary, args.process_binary)
    try:
        if args.static_only and any(binaries):
            raise AuditError("--static-only cannot be combined with replay binaries")
        if any(binaries) and not all(binaries):
            raise AuditError("replay requires all three reviewed binary paths")
        bundle = verify_bundle(repo_root, args.audit)
        replayed = all(binaries)
        if replayed:
            assert args.t1_binary and args.worker_binary and args.process_binary
            replay(bundle, args.t1_binary, args.worker_binary, args.process_binary)
        print(render_audit_report(bundle, replayed=replayed), end="")
    except (AuditError, OSError) as error:
        print(f"S3 trusted-thesis audit: FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
