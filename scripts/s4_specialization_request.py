#!/usr/bin/env python3
"""Validate and replay the clock-free S4-WP5A specialization request."""

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

import s4_residual_role as wp5


CONTRACT_MAGIC = "NAUX-S4-SPECIALIZATION-REQUEST-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-SPECIALIZATION-REQUEST-AUTHORITY\t1"
REQUEST_MAGIC = "NAUX-S4-SPECIALIZATION-REQUEST\t1"
REPORT_MAGIC = "NAUX-S4-SPECIALIZATION-REQUEST-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-specialization-request:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-specialization-request:authority:v1\0"
SOURCE_DOMAIN = b"NAUX:s4-specialization-request:source:v1\0"
WORK_DOMAIN = b"NAUX:s4-specialization-request:work:v1\0"
RECORD_DOMAIN = b"NAUX:s4-specialization-request:record:v1\0"
EVIDENCE_DOMAIN = b"NAUX:s4-specialization-request:evidence:v1\0"
REPORT_DOMAIN = b"NAUX:s4-specialization-request:report:v1\0"
WP5_AUTHORITY_SEAL = "93353f2d40cb1217b4b37a30f04c9807ecde9d98d7e4e370a99286fbe355bf5d"
CORPUS_SEAL = "793fdac34e1b0536365208a745ad59edaf6dbb94eabcede88d273292861dffa5"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")
MAX_REPORT_BYTES = 65_536

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("request-status", "admitted"),
    ("residual-status", "unavailable"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("dataset", "static-n16384-r50"),
    ("frontend", "ordinary-naux-frontend"),
    ("pipeline", "single-general-future-residual-pipeline"),
    ("kernel-count", "4"),
    ("corpus-seal", CORPUS_SEAL),
    ("work-obligations", "allocation-initialization-kernel-checksum-teardown"),
)
WORK = (
    "owned-runtime-list",
    "range-zero-through-n-minus-one",
    "reps-times-full-n-source-semantics",
    "exact-corpus-oracle-after-dynamic-work",
    "release-owned-list-before-completion",
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP5A"),
    ("authority-id", "s4-specialization-request-v1"),
    ("request-status", "admitted"),
    ("residual-status", "unavailable"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("kernel-count", "4"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-specialization-request.yml",
    "distribution/s4-performance/WP5A-NONCLAIMS.md",
    "distribution/s4-performance/WP5A-README.md",
    "distribution/s4-performance/WP5A-REQUEST.tsv",
    "naux-lang/examples/naux_s4_specialization_request.rs",
    "scripts/s4_specialization_request.py",
    "scripts/tests/test_s4_specialization_request.py",
)
EXPECTED_COLUMNS = (
    "columns\tordinal\tkernel\tn\treps\toracle\tsource-path\tsource-hash\t"
    "program-hash\twork-hash\trecord-hash"
)
FORBIDDEN_TIMING = (
    "instant::",
    "systemtime::",
    ".elapsed()",
    "duration_since(",
    "runtime_ns",
    "compile_ns",
    "runtime-ns",
    "compile-ns",
    "throughput",
    "latency",
    "median",
)


class RequestError(RuntimeError):
    """A fail-closed S4-WP5A request error."""


@dataclass(frozen=True)
class ContractRecord:
    ordinal: int
    name: str
    source_path: str
    source_sha256: str
    n: int
    reps: int
    oracle: int
    work: tuple[str, ...]


@dataclass(frozen=True)
class Contract:
    records: tuple[ContractRecord, ...]
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
class CandidateRecord:
    ordinal: int
    name: str
    n: int
    reps: int
    oracle: int
    source_path: str
    source_hash: str
    program_hash: str
    work_hash: str
    record_hash: str


@dataclass(frozen=True)
class Candidate:
    records: tuple[CandidateRecord, ...]
    evidence_hash: str
    raw: bytes


@dataclass(frozen=True)
class Admission:
    contract: Contract
    authority: Authority
    report: bytes
    report_root: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(raw: bytes, label: str, *, limit: int) -> list[str]:
    if not raw or len(raw) > limit or not raw.endswith(b"\n"):
        raise RequestError(f"{label} has invalid extent")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RequestError(f"{label} is not UTF-8") from error
    if "\r" in text or "\x00" in text:
        raise RequestError(f"{label} is not canonical LF text")
    lines = text.splitlines()
    if any(not line for line in lines):
        raise RequestError(f"{label} contains a blank row")
    return lines


def _read(path: Path, *, limit: int = 8_000_000) -> tuple[bytes, list[str]]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise RequestError(f"cannot read S4-WP5A input: {path}") from error
    return raw, _canonical_bytes(raw, path.as_posix(), limit=limit)


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    _raw, lines = _read(path)
    if len(lines) < 3 or lines[0] != magic:
        raise RequestError(f"unsupported sealed schema: {path}")
    if not lines[-1].startswith("seal\t") or any(
        line.startswith("seal\t") for line in lines[:-1]
    ):
        raise RequestError(f"terminal seal missing or duplicated: {path}")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise RequestError(f"invalid terminal seal: {path}")
    body = "".join(f"{line}\n" for line in lines[:-1]).encode()
    if _sha256(domain + body) != fields[1]:
        raise RequestError(f"seal mismatch: {path}")
    return lines[1:-1], fields[1]


def _uint(value: str, label: str, maximum: int = (1 << 64) - 1) -> int:
    if not UINT_RE.fullmatch(value) or int(value) > maximum:
        raise RequestError(f"invalid unsigned integer in {label}")
    return int(value)


def _int(value: str, label: str) -> int:
    if not INT_RE.fullmatch(value):
        raise RequestError(f"invalid signed integer in {label}")
    parsed = int(value)
    if parsed < -(1 << 63) or parsed >= 1 << 63:
        raise RequestError(f"signed integer exceeds i64 in {label}")
    return parsed


def _hash(value: str, label: str) -> str:
    if not HASH_RE.fullmatch(value):
        raise RequestError(f"invalid SHA-256 in {label}")
    return value


def parse_contract(path: Path, root: Path, corpus: object) -> Contract:
    lines, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if len(lines) != len(CONTRACT_METADATA) + 4:
        raise RequestError("unexpected specialization-request contract row count")
    metadata: list[tuple[str, str]] = []
    for line in lines[: len(CONTRACT_METADATA)]:
        fields = line.split("\t")
        if len(fields) != 3 or fields[0] != "meta":
            raise RequestError("invalid specialization-request metadata row")
        metadata.append((fields[1], fields[2]))
    if tuple(metadata) != CONTRACT_METADATA:
        raise RequestError("specialization-request metadata drifted")

    records: list[ContractRecord] = []
    for index, (line, kernel) in enumerate(
        zip(lines[len(CONTRACT_METADATA) :], corpus.kernels), start=1
    ):
        fields = line.split("\t")
        if len(fields) != 13 or fields[0] != "kernel":
            raise RequestError("invalid specialization-request kernel row")
        source_path = fields[3]
        source_raw = (root / source_path).read_bytes()
        record = ContractRecord(
            ordinal=index,
            name=fields[2],
            source_path=source_path,
            source_sha256=_hash(fields[4], f"{kernel.name} source SHA-256"),
            n=_uint(fields[5], f"{kernel.name} n"),
            reps=_uint(fields[6], f"{kernel.name} reps"),
            oracle=_int(fields[7], f"{kernel.name} oracle"),
            work=tuple(fields[8:13]),
        )
        if (
            fields[1] != f"{index:02}"
            or record.name != kernel.name
            or record.source_path != kernel.naux_source
            or record.source_sha256 != _sha256(source_raw)
            or record.n != kernel.n
            or record.reps != kernel.reps
            or record.oracle != kernel.expected
            or record.work != WORK
        ):
            raise RequestError(f"request contract drifted for {kernel.name}")
        records.append(record)
    if len(records) != 4:
        raise RequestError("specialization request does not contain four kernels")
    return Contract(tuple(records), seal)


def _safe_path(value: str) -> None:
    if not PATH_RE.fullmatch(value):
        raise RequestError("invalid S4-WP5A authority path")
    parsed = Path(value)
    if parsed.is_absolute() or "." in parsed.parts or ".." in parsed.parts:
        raise RequestError("traversing S4-WP5A authority path")


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    expected = len(AUTHORITY_METADATA) + 2 + len(EXPECTED_FILES)
    if len(lines) != expected:
        raise RequestError("unexpected S4-WP5A authority row count")
    metadata: list[tuple[str, str]] = []
    for line in lines[: len(AUTHORITY_METADATA)]:
        fields = line.split("\t")
        if len(fields) != 3 or fields[0] != "meta":
            raise RequestError("invalid S4-WP5A authority metadata row")
        metadata.append((fields[1], fields[2]))
    if tuple(metadata) != AUTHORITY_METADATA:
        raise RequestError("unexpected S4-WP5A authority metadata")
    cursor = len(AUTHORITY_METADATA)
    component = tuple(lines[cursor].split("\t"))
    if component != (
        "component",
        "specialization-request-contract",
        "distribution/s4-performance/WP5A-REQUEST.tsv",
        contract_seal,
    ):
        raise RequestError("unexpected S4-WP5A contract component")
    cursor += 1
    parent = tuple(lines[cursor].split("\t"))
    expected_parent = (
        "parent",
        "residual-role-authority",
        "distribution/s4-performance/WP5-AUTHORITY.tsv",
        WP5_AUTHORITY_SEAL,
    )
    if parent != expected_parent:
        raise RequestError("unexpected S4-WP5A parent authority")
    cursor += 1
    files: list[FileRecord] = []
    for line in lines[cursor:]:
        fields = line.split("\t")
        if len(fields) != 5 or fields[0] != "file":
            raise RequestError("invalid S4-WP5A file row")
        if not MODE_RE.fullmatch(fields[1]) or not UINT_RE.fullmatch(fields[2]):
            raise RequestError("invalid S4-WP5A file metadata")
        _safe_path(fields[4])
        files.append(
            FileRecord(
                int(fields[1], 8),
                int(fields[2]),
                _hash(fields[3], "authority file"),
                fields[4],
            )
        )
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise RequestError("unexpected S4-WP5A file inventory")
    return Authority(tuple(metadata), parent[1:], tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        try:
            info = path.lstat()
        except OSError as error:
            raise RequestError(f"missing bound S4-WP5A file: {record.path}") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RequestError(f"bound S4-WP5A path is not regular: {record.path}")
        raw = path.read_bytes()
        mode = stat.S_IFREG | stat.S_IMODE(info.st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise RequestError(f"bound S4-WP5A file drifted: {record.path}")


def _verify_source_boundary(root: Path, corpus: object) -> None:
    source = (root / "naux-lang/examples/naux_s4_specialization_request.rs").read_text()
    workflow = (root / ".github/workflows/s4-specialization-request.yml").read_text()
    required_source = (
        'include_str!("../../distribution/s4-performance/WP5A-REQUEST.tsv")',
        'include_str!("../../distribution/s4-performance/CORPUS.tsv")',
        "lexer::lex(source)",
        "parser::parse_script(&tokens)",
        "typecheck::check_program(&statements)",
        "compile_script(&statements)",
        "verify_request(&evidence)",
        "reps-times-full-n-source-semantics",
        "release-owned-list-before-completion",
    )
    if any(token not in source for token in required_source):
        raise RequestError("ordinary frontend or work binding is incomplete")
    lowered = source.lower()
    if any(token in lowered for token in FORBIDDEN_TIMING):
        raise RequestError("clock or performance token entered request emitter")
    if any(str(kernel.expected) in source for kernel in corpus.kernels):
        raise RequestError("direct oracle literal entered request emitter")
    forbidden_source = (
        "benchmarks/c/",
        "benchmarks/rust/",
        "match record.name",
        "match kernel.name",
        "run_untimed(",
        "typedrunner",
        "write_elf",
    )
    if any(token in lowered for token in forbidden_source):
        raise RequestError("execution, host oracle, or artifact generation entered request emitter")
    required_workflow = (
        "python3 scripts/s4_specialization_request.py",
        "--example naux_s4_specialization_request",
        "scripts.tests.test_s4_specialization_request",
        "--binary target/release/examples/naux_s4_specialization_request",
    )
    if any(token not in workflow for token in required_workflow):
        raise RequestError("S4-WP5A workflow does not replay the reviewed request")
    lowered_workflow = workflow.lower()
    if any(token in lowered_workflow for token in FORBIDDEN_TIMING):
        raise RequestError("timing entered the S4-WP5A workflow")
    expected = {
        "WP5A-AUTHORITY.tsv",
        "WP5A-NONCLAIMS.md",
        "WP5A-README.md",
        "WP5A-REQUEST.tsv",
    }
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP5A-*")
        if path.is_file()
    }
    if actual != expected:
        raise RequestError("unexpected S4-WP5A distribution artifact")


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def _i64(value: int) -> bytes:
    return struct.pack("<q", value)


def _string(value: str) -> bytes:
    raw = value.encode()
    return _u32(len(raw)) + raw


def _work_hash(work: tuple[str, ...]) -> str:
    body = bytearray(_u32(len(work)))
    for value in work:
        body.extend(_string(value))
    return _sha256(WORK_DOMAIN + body)


def _record_hash(record: CandidateRecord) -> str:
    body = bytearray()
    body.extend(_u32(record.ordinal))
    body.extend(_string(record.name))
    body.extend(_string(record.source_path))
    body.extend(_u64(record.n))
    body.extend(_u64(record.reps))
    body.extend(_i64(record.oracle))
    body.extend(bytes.fromhex(record.source_hash))
    body.extend(bytes.fromhex(record.program_hash))
    body.extend(bytes.fromhex(record.work_hash))
    return _sha256(RECORD_DOMAIN + body)


def _evidence_hash(contract: Contract, records: tuple[CandidateRecord, ...]) -> str:
    body = bytearray()
    for value in (0, 1, 0, 1, 0, 0):
        body.extend(struct.pack("<H", value))
    body.extend(bytes.fromhex(contract.seal))
    body.extend(bytes.fromhex(CORPUS_SEAL))
    body.extend(_u32(len(records)))
    for record in records:
        body.extend(bytes.fromhex(record.record_hash))
    return _sha256(EVIDENCE_DOMAIN + body)


def parse_candidate(raw: bytes, root: Path, contract: Contract) -> Candidate:
    lines = _canonical_bytes(raw, "request stdout", limit=MAX_REPORT_BYTES)
    lowered = raw.lower()
    if any(token.encode() in lowered for token in FORBIDDEN_TIMING):
        raise RequestError("timing or performance field entered request stdout")
    if len(lines) != 14 or lines[0] != REQUEST_MAGIC:
        raise RequestError("unexpected specialization-request report shape")
    expected_header = (
        "meta\tschema\t0.1.0",
        "meta\tpolicy\t1.0.0",
        f"meta\tcontract\t{contract.seal}",
        f"meta\tcorpus\t{CORPUS_SEAL}",
        "meta\tfrontend\tordinary-naux-frontend",
        "meta\tresidual\tunavailable",
        EXPECTED_COLUMNS,
    )
    if tuple(lines[1:8]) != expected_header:
        raise RequestError("specialization-request header drifted")
    records: list[CandidateRecord] = []
    expected_work_hash = _work_hash(WORK)
    for line, accepted in zip(lines[8:12], contract.records):
        fields = line.split("\t")
        if len(fields) != 11 or fields[0] != "kernel":
            raise RequestError("invalid specialization-request record")
        record = CandidateRecord(
            ordinal=accepted.ordinal,
            name=fields[2],
            n=_uint(fields[3], "record n"),
            reps=_uint(fields[4], "record reps"),
            oracle=_int(fields[5], "record oracle"),
            source_path=fields[6],
            source_hash=_hash(fields[7], "record source hash"),
            program_hash=_hash(fields[8], "record program hash"),
            work_hash=_hash(fields[9], "record work hash"),
            record_hash=_hash(fields[10], "record seal"),
        )
        source_raw = (root / accepted.source_path).read_bytes()
        expected_source_hash = _sha256(SOURCE_DOMAIN + source_raw)
        if (
            fields[1] != f"{accepted.ordinal:02}"
            or record.name != accepted.name
            or record.n != accepted.n
            or record.reps != accepted.reps
            or record.oracle != accepted.oracle
            or record.source_path != accepted.source_path
            or record.source_hash != expected_source_hash
            or record.work_hash != expected_work_hash
            or record.record_hash != _record_hash(record)
        ):
            raise RequestError(f"specialization request drifted for {accepted.name}")
        records.append(record)
    record_tuple = tuple(records)
    evidence_fields = lines[12].split("\t")
    if len(evidence_fields) != 2 or evidence_fields[0] != "evidence":
        raise RequestError("invalid specialization-request evidence row")
    evidence_hash = _hash(evidence_fields[1], "request evidence")
    if evidence_hash != _evidence_hash(contract, record_tuple):
        raise RequestError("specialization-request evidence mismatch")
    if lines[13] != "verification\tregenerated":
        raise RequestError("regenerative request verification is missing")
    return Candidate(record_tuple, evidence_hash, raw)


def _binary_path(value: Path) -> Path:
    binary = value.resolve()
    try:
        info = binary.stat()
    except OSError as error:
        raise RequestError("S4-WP5A request binary is missing") from error
    if not stat.S_ISREG(info.st_mode) or not os.access(binary, os.X_OK):
        raise RequestError("S4-WP5A request binary is not executable")
    return binary


def _run(binary: Path) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("NAUX_"):
            environment.pop(name)
    environment.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    try:
        return subprocess.run(
            [str(binary)],
            input=b"",
            capture_output=True,
            check=False,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RequestError("fixed-argv request process failed") from error


def _report(authority: Authority, contract: Contract, mode: str, extras: list[str]) -> tuple[bytes, str]:
    lines = [
        REPORT_MAGIC,
        "request-status\tadmitted",
        "residual-status\tunavailable",
        "claim-status\tnot-admitted",
        "timing-status\tforbidden",
        f"mode\t{mode}",
        f"wp5-authority-seal\t{WP5_AUTHORITY_SEAL}",
        f"request-contract-seal\t{contract.seal}",
        f"wp5a-authority-seal\t{authority.seal}",
        f"files\t{len(authority.files)}",
    ]
    lines.extend(extras)
    body = "".join(f"{line}\n" for line in lines).encode()
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve()
    parent = wp5.validate(root)
    if parent.authority.seal != WP5_AUTHORITY_SEAL:
        raise RequestError("accepted S4-WP5 authority drifted")
    wp1_admission = wp5.wp4.wp3.wp2.wp1.validate(root)
    contract = parse_contract(
        root / "distribution/s4-performance/WP5A-REQUEST.tsv",
        root,
        wp1_admission.corpus,
    )
    authority = parse_authority(
        root / "distribution/s4-performance/WP5A-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_source_boundary(root, wp1_admission.corpus)
    extras = [
        f"request\t{record.ordinal:02}\t{record.name}\t{record.n}\t{record.reps}\t{record.source_sha256}"
        for record in contract.records
    ]
    extras.extend(
        (
            "blocker\tresidual-generator-unavailable",
            "blocker\tfour-artifact-replay-unavailable",
            "blocker\tuntimed-role-admission-unavailable",
        )
    )
    report, report_root = _report(authority, contract, "static", extras)
    return Admission(contract, authority, report, report_root)


def replay(root: Path, admission: Admission, binary_value: Path) -> tuple[bytes, str]:
    root = root.resolve()
    binary = _binary_path(binary_value)
    candidates: list[Candidate] = []
    for _ in range(2):
        completed = _run(binary)
        if completed.returncode != 0 or completed.stderr != b"":
            raise RequestError("request emitter failed or emitted diagnostics")
        candidates.append(parse_candidate(completed.stdout, root, admission.contract))
    if candidates[0] != candidates[1]:
        raise RequestError("specialization-request replay is not deterministic")
    candidate = candidates[0]
    extras = [
        f"request-evidence\t{candidate.evidence_hash}",
        f"request-bytes\t{len(candidate.raw)}",
    ]
    extras.extend(
        f"kernel\t{record.ordinal:02}\t{record.name}\t{record.program_hash}\t{record.record_hash}"
        for record in candidate.records
    )
    extras.extend(
        (
            "replays\t2",
            "blocker\tresidual-generator-unavailable",
            "blocker\tfour-artifact-replay-unavailable",
            "blocker\tuntimed-role-admission-unavailable",
        )
    )
    return _report(admission.authority, admission.contract, "untimed-request-replay", extras)


def _default_root() -> Path:
    return Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=_default_root())
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        admission = validate(args.root)
        report = admission.report
        if args.binary is not None:
            report, _root = replay(args.root, admission, args.binary)
        if args.report is None:
            sys.stdout.buffer.write(report)
        else:
            args.report.write_bytes(report)
    except (RequestError, wp5.ResidualRoleError, OSError) as error:
        print(f"S4 specialization request rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
