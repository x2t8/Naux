#!/usr/bin/env python3
"""Validate and replay the untimed S4-WP3 NAUX native corpus carrier."""

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

import s4_reference_baselines as wp2


AUTHORITY_MAGIC = "NAUX-S4-NATIVE-CARRIER-AUTHORITY\t1"
CANDIDATE_MAGIC = "NAUX-S4-NATIVE-CANDIDATE\t1"
REPORT_MAGIC = "NAUX-S4-NATIVE-CARRIER-REPORT\t1"
AUTHORITY_DOMAIN = b"NAUX:s4-native-carrier:authority:v1\0"
SOURCE_DOMAIN = b"NAUX:s4:native-candidate:source:v1\0"
RECORD_DOMAIN = b"NAUX:s4:native-candidate:record:v1\0"
EVIDENCE_DOMAIN = b"NAUX:s4:native-candidate:evidence:v1\0"
REPORT_DOMAIN = b"NAUX:s4-native-carrier:report:v1\0"
WP1_AUTHORITY_SEAL = "b23533c4e96ec9e3b66482e96b79fdeb5985c823ce012d827e69eb1c14a4b659"
WP2_AUTHORITY_SEAL = "0361c1e0d90bc3ba8d9a1e0bead7466bd71be3e3a723d605606730144ae7db6a"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")
MAX_REPORT_BYTES = 65_536

AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP3"),
    ("authority-id", "s4-naux-native-carrier-v1"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("kernel-count", "4"),
    ("file-count", "38"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-native-carrier.yml",
    "Cargo.lock",
    "naux-lang/Cargo.toml",
    "naux-lang/examples/naux_s4_native_carrier.rs",
    "naux-lang/src/ask/mod.rs",
    "naux-lang/src/ask/stub.rs",
    "naux-lang/src/ast.rs",
    "naux-lang/src/core/encoding.rs",
    "naux-lang/src/core/mod.rs",
    "naux-lang/src/core/schema.rs",
    "naux-lang/src/diagnostic.rs",
    "naux-lang/src/lexer.rs",
    "naux-lang/src/lib.rs",
    "naux-lang/src/parser/error.rs",
    "naux-lang/src/parser/mod.rs",
    "naux-lang/src/parser/parser.rs",
    "naux-lang/src/parser/utils.rs",
    "naux-lang/src/runtime/env.rs",
    "naux-lang/src/runtime/error.rs",
    "naux-lang/src/runtime/events.rs",
    "naux-lang/src/runtime/mod.rs",
    "naux-lang/src/runtime/value.rs",
    "naux-lang/src/s4_native_carrier.rs",
    "naux-lang/src/token.rs",
    "naux-lang/src/typecheck.rs",
    "naux-lang/src/vm/bytecode.rs",
    "naux-lang/src/vm/compiler.rs",
    "naux-lang/src/vm/egraph.rs",
    "naux-lang/src/vm/ir.rs",
    "naux-lang/src/vm/jit.rs",
    "naux-lang/src/vm/mod.rs",
    "naux-lang/src/vm/ssa.rs",
    "naux-lang/src/vm/typed.rs",
    "naux-lang/src/vm/value_bits.rs",
    "distribution/s4-performance/WP3-NONCLAIMS.md",
    "distribution/s4-performance/WP3-README.md",
    "scripts/s4_native_carrier.py",
    "scripts/tests/test_s4_native_carrier.py",
)
EXPECTED_COLUMNS = (
    "columns\tordinal\tkernel\tresult\tsource\tprogram\ttraces\thits\t"
    "static-branches\tcode-bytes\thot-code-bytes\tdeopts\tside-exits\t"
    "guard-failures\tinterpreter-index-elements\tlist-range-calls\trecord"
)
FORBIDDEN_REPORT_TOKENS = (
    "runtime-ns",
    "compile-ns",
    "elapsed",
    "duration",
    "median",
    "throughput",
    "latency",
)
FORBIDDEN_CARRIER_TOKENS = (
    "Instant::",
    "SystemTime::",
    ".elapsed()",
    "duration_since(",
    "runtime_ns",
    "compile_ns",
)


class CarrierError(RuntimeError):
    """A fail-closed S4-WP3 carrier error."""


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
class CandidateRecord:
    ordinal: int
    name: str
    result: int
    source_hash: str
    program_hash: str
    trace_count: int
    native_trace_hits: int
    static_branches: int
    code_bytes: int
    hot_code_bytes: int
    deopts: int
    side_exits: int
    guard_failures: int
    interpreter_index_elements: int
    list_range_calls: int
    record_hash: str


@dataclass(frozen=True)
class Candidate:
    records: tuple[CandidateRecord, ...]
    corpus_hash: str
    evidence_hash: str
    raw: bytes


@dataclass(frozen=True)
class Admission:
    authority: Authority
    corpus: object
    report: bytes
    report_root: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_canonical(
    path: Path, *, limit: int = 8_000_000, allow_blank: bool = False
) -> tuple[bytes, list[str]]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CarrierError(f"cannot read S4-WP3 input: {path}") from error
    return _canonical_bytes(raw, path.as_posix(), limit=limit, allow_blank=allow_blank)


def _canonical_bytes(
    raw: bytes, label: str, *, limit: int, allow_blank: bool = False
) -> tuple[bytes, list[str]]:
    if len(raw) > limit:
        raise CarrierError(f"S4-WP3 input exceeds size limit: {label}")
    if not raw.endswith(b"\n"):
        raise CarrierError(f"S4-WP3 input must end with LF: {label}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CarrierError(f"S4-WP3 input must be UTF-8: {label}") from error
    if "\r" in text or "\x00" in text:
        raise CarrierError(f"S4-WP3 input is not canonical LF text: {label}")
    lines = text.splitlines()
    if not allow_blank and any(not line for line in lines):
        raise CarrierError(f"blank S4-WP3 rows are forbidden: {label}")
    return raw, lines


def _safe_path(value: str) -> None:
    if not PATH_RE.fullmatch(value):
        raise CarrierError("invalid S4-WP3 authority path")
    path = Path(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise CarrierError("non-relative or traversing S4-WP3 authority path")


def parse_authority(path: Path) -> Authority:
    _raw, lines = _read_canonical(path)
    if not lines or lines[0] != AUTHORITY_MAGIC:
        raise CarrierError("unsupported S4-WP3 authority schema")
    if len(lines) < 4 or not lines[-1].startswith("seal\t"):
        raise CarrierError("missing terminal S4-WP3 authority seal")
    if any(line.startswith("seal\t") for line in lines[:-1]):
        raise CarrierError("S4-WP3 authority seal must be terminal and unique")
    seal_fields = lines[-1].split("\t")
    if len(seal_fields) != 2 or not HASH_RE.fullmatch(seal_fields[1]):
        raise CarrierError("invalid S4-WP3 authority seal")
    body = "".join(f"{line}\n" for line in lines[:-1]).encode()
    expected_seal = _sha256(AUTHORITY_DOMAIN + body)
    if seal_fields[1] != expected_seal:
        raise CarrierError("S4-WP3 authority seal mismatch")

    rows = lines[1:-1]
    metadata_rows = rows[: len(AUTHORITY_METADATA)]
    metadata: list[tuple[str, str]] = []
    for line in metadata_rows:
        fields = line.split("\t")
        if len(fields) != 3 or fields[0] != "meta":
            raise CarrierError("invalid S4-WP3 authority metadata row")
        metadata.append((fields[1], fields[2]))
    if tuple(metadata) != AUTHORITY_METADATA:
        raise CarrierError("unexpected S4-WP3 authority metadata")

    remaining = rows[len(AUTHORITY_METADATA) :]
    expected_parents = (
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
    )
    if len(remaining) != len(expected_parents) + len(EXPECTED_FILES):
        raise CarrierError("unexpected S4-WP3 authority row count")
    parents: list[tuple[str, str, str]] = []
    for line in remaining[:2]:
        fields = line.split("\t")
        if len(fields) != 4 or fields[0] != "parent":
            raise CarrierError("invalid S4-WP3 parent row")
        parents.append((fields[1], fields[2], fields[3]))
    if tuple(parents) != expected_parents:
        raise CarrierError("unexpected S4-WP3 parent authority binding")

    files: list[FileRecord] = []
    for line in remaining[2:]:
        fields = line.split("\t")
        if len(fields) != 5 or fields[0] != "file":
            raise CarrierError("invalid S4-WP3 authority file row")
        if not MODE_RE.fullmatch(fields[1]):
            raise CarrierError("invalid S4-WP3 authority file mode")
        if not UINT_RE.fullmatch(fields[2]) or int(fields[2]) > 8_000_000:
            raise CarrierError("invalid S4-WP3 authority file size")
        if not HASH_RE.fullmatch(fields[3]):
            raise CarrierError("invalid S4-WP3 authority file hash")
        _safe_path(fields[4])
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise CarrierError("unexpected S4-WP3 authority file inventory")
    return Authority(tuple(metadata), tuple(parents), tuple(files), seal_fields[1])


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        try:
            info = path.lstat()
        except OSError as error:
            raise CarrierError(f"missing bound S4-WP3 file: {record.path}") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise CarrierError(f"bound S4-WP3 path is not a regular file: {record.path}")
        actual_mode = stat.S_IFREG | stat.S_IMODE(info.st_mode)
        raw = path.read_bytes()
        if actual_mode != record.mode:
            raise CarrierError(f"bound S4-WP3 mode mismatch: {record.path}")
        if len(raw) != record.size:
            raise CarrierError(f"bound S4-WP3 size mismatch: {record.path}")
        if _sha256(raw) != record.sha256:
            raise CarrierError(f"bound S4-WP3 hash mismatch: {record.path}")


def _verify_source_boundary(root: Path, corpus: object) -> None:
    carrier = (root / "naux-lang/src/s4_native_carrier.rs").read_text(encoding="utf-8")
    binary = (root / "naux-lang/examples/naux_s4_native_carrier.rs").read_text(
        encoding="utf-8"
    )
    typed = (root / "naux-lang/src/vm/typed.rs").read_text(encoding="utf-8")
    required_carrier = (
        "include_str!(\"../../distribution/s4-performance/CORPUS.tsv\")",
        "lexer::lex(source)",
        "parser::parse_script(&tokens)",
        "typecheck::check_program(&statements)",
        "compile_script(&statements)",
        ".run_untimed(&program)",
        "path.interp_index_elements != 0",
        "native_trace_hits == 0",
        "verify_s4_native_candidate",
    )
    if any(token not in carrier for token in required_carrier):
        raise CarrierError("S4-WP3 carrier source boundary is incomplete")
    if any(token in carrier for token in FORBIDDEN_CARRIER_TOKENS):
        raise CarrierError("clock or performance-claim token entered the S4-WP3 carrier")
    if any(str(kernel.expected) in carrier for kernel in corpus.kernels):
        raise CarrierError("direct oracle literal entered the S4-WP3 carrier")
    required_binary = (
        "emit_s4_native_candidate",
        "verify_s4_native_candidate",
        "render_s4_native_candidate",
    )
    if any(token not in binary for token in required_binary) or "Instant::" in binary:
        raise CarrierError("S4-WP3 carrier binary boundary is incomplete")
    untimed_start = typed.find("pub fn run_untimed(")
    untimed_end = typed.find("\n    fn run_internal(", untimed_start)
    if untimed_start < 0 or untimed_end < 0:
        raise CarrierError("typed untimed execution API is missing")
    untimed_body = typed[untimed_start:untimed_end]
    if "run_internal(prog, None, false)" not in untimed_body or "Instant::" in untimed_body:
        raise CarrierError("typed untimed execution API sampled a clock or changed policy")
    dispatch_tokens = (
        "let entry_key = (code_id, ip);",
        "trace_cache.get(&entry_key)",
        "then_some(entry.back_edge)",
    )
    if any(token not in typed for token in dispatch_tokens):
        raise CarrierError("general cached trace-entry dispatch is missing")


def _report(authority: Authority, mode: str, extras: list[str]) -> tuple[bytes, str]:
    lines = [
        REPORT_MAGIC,
        "claim-status\tnot-admitted",
        "timing-status\tforbidden",
        f"mode\t{mode}",
        f"wp1-authority-seal\t{WP1_AUTHORITY_SEAL}",
        f"wp2-authority-seal\t{WP2_AUTHORITY_SEAL}",
        f"wp3-authority-seal\t{authority.seal}",
        f"files\t{len(authority.files)}",
    ]
    lines.extend(extras)
    body = "".join(f"{line}\n" for line in lines).encode()
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve()
    wp2_admission = wp2.validate(root)
    if wp2_admission.authority.seal != WP2_AUTHORITY_SEAL:
        raise CarrierError("accepted S4-WP2 authority drifted")
    wp1_admission = wp2.wp1.validate(root)
    if wp1_admission.authority.seal != WP1_AUTHORITY_SEAL:
        raise CarrierError("accepted S4-WP1 authority drifted")
    authority = parse_authority(root / "distribution/s4-performance/WP3-AUTHORITY.tsv")
    _verify_files(root, authority)
    _verify_source_boundary(root, wp1_admission.corpus)
    extras = [
        f"oracle\t{kernel.ordinal}\t{kernel.name}\t{kernel.expected}"
        for kernel in wp1_admission.corpus.kernels
    ]
    report, report_root = _report(authority, "static", extras)
    return Admission(authority, wp1_admission.corpus, report, report_root)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def _i64(value: int) -> bytes:
    return struct.pack("<q", value)


def _string(value: str) -> bytes:
    raw = value.encode()
    return _u32(len(raw)) + raw


def _uint(value: str, label: str, *, maximum: int = (1 << 64) - 1) -> int:
    if not UINT_RE.fullmatch(value):
        raise CarrierError(f"non-canonical unsigned integer in {label}")
    parsed = int(value)
    if parsed > maximum:
        raise CarrierError(f"unsigned integer exceeds bound in {label}")
    return parsed


def _int(value: str, label: str) -> int:
    if not INT_RE.fullmatch(value):
        raise CarrierError(f"non-canonical signed integer in {label}")
    parsed = int(value)
    if parsed < -(1 << 63) or parsed >= 1 << 63:
        raise CarrierError(f"signed integer exceeds i64 in {label}")
    return parsed


def _hash(value: str, label: str) -> str:
    if not HASH_RE.fullmatch(value):
        raise CarrierError(f"invalid SHA-256 in {label}")
    return value


def _record_hash(record: CandidateRecord) -> str:
    body = bytearray()
    body.extend(_u32(record.ordinal))
    body.extend(_string(record.name))
    body.extend(bytes.fromhex(record.source_hash))
    body.extend(bytes.fromhex(record.program_hash))
    body.extend(_i64(record.result))
    body.extend(_u32(record.trace_count))
    for value in (
        record.native_trace_hits,
        record.static_branches,
        record.code_bytes,
        record.hot_code_bytes,
        record.deopts,
        record.side_exits,
        record.guard_failures,
        record.interpreter_index_elements,
        record.list_range_calls,
    ):
        body.extend(_u64(value))
    return _sha256(RECORD_DOMAIN + body)


def _evidence_hash(corpus_hash: str, records: tuple[CandidateRecord, ...]) -> str:
    body = bytearray()
    for value in (0, 1, 0, 1, 0, 0):
        body.extend(struct.pack("<H", value))
    body.extend(bytes.fromhex(corpus_hash))
    body.extend(_u32(len(records)))
    for record in records:
        body.extend(bytes.fromhex(record.record_hash))
    return _sha256(EVIDENCE_DOMAIN + body)


def parse_candidate(raw: bytes, root: Path, corpus: object) -> Candidate:
    _raw, lines = _canonical_bytes(raw, "carrier stdout", limit=MAX_REPORT_BYTES)
    if any(token.encode() in raw.lower() for token in FORBIDDEN_REPORT_TOKENS):
        raise CarrierError("timing or performance-claim field entered carrier stdout")
    if len(lines) != 11 or lines[0] != CANDIDATE_MAGIC:
        raise CarrierError("unexpected S4-WP3 candidate report shape")
    corpus_raw = (root / "distribution/s4-performance/CORPUS.tsv").read_bytes()
    corpus_hash = _sha256(SOURCE_DOMAIN + corpus_raw)
    expected_meta = (
        "meta\tschema\t0.1.0",
        "meta\tpolicy\t1.0.0",
        f"meta\tcorpus\t{corpus_hash}",
        EXPECTED_COLUMNS,
    )
    if tuple(lines[1:5]) != expected_meta:
        raise CarrierError("unexpected S4-WP3 candidate metadata or columns")

    records: list[CandidateRecord] = []
    for index, (line, kernel) in enumerate(zip(lines[5:9], corpus.kernels), start=1):
        fields = line.split("\t")
        if len(fields) != 17 or fields[0] != "kernel":
            raise CarrierError("invalid S4-WP3 candidate kernel row")
        if fields[1] != f"{index:02}" or fields[2] != kernel.name:
            raise CarrierError("S4-WP3 candidate kernel order drifted")
        source_raw = (root / kernel.naux_source).read_bytes()
        expected_source_hash = _sha256(SOURCE_DOMAIN + source_raw)
        record = CandidateRecord(
            ordinal=index,
            name=fields[2],
            result=_int(fields[3], f"{kernel.name} result"),
            source_hash=_hash(fields[4], f"{kernel.name} source hash"),
            program_hash=_hash(fields[5], f"{kernel.name} program hash"),
            trace_count=_uint(fields[6], f"{kernel.name} trace count", maximum=64),
            native_trace_hits=_uint(fields[7], f"{kernel.name} native hits"),
            static_branches=_uint(fields[8], f"{kernel.name} static branches"),
            code_bytes=_uint(fields[9], f"{kernel.name} code bytes", maximum=1_048_576),
            hot_code_bytes=_uint(
                fields[10], f"{kernel.name} hot code bytes", maximum=1_048_576
            ),
            deopts=_uint(fields[11], f"{kernel.name} deopts"),
            side_exits=_uint(fields[12], f"{kernel.name} side exits"),
            guard_failures=_uint(fields[13], f"{kernel.name} guard failures"),
            interpreter_index_elements=_uint(
                fields[14], f"{kernel.name} interpreter index elements"
            ),
            list_range_calls=_uint(fields[15], f"{kernel.name} list range calls"),
            record_hash=_hash(fields[16], f"{kernel.name} record hash"),
        )
        if record.result != kernel.expected or record.source_hash != expected_source_hash:
            raise CarrierError(f"semantic or source mismatch for {kernel.name}")
        if (
            record.trace_count != 1
            or record.native_trace_hits != kernel.reps
            or record.static_branches == 0
            or record.code_bytes == 0
            or record.hot_code_bytes == 0
            or record.hot_code_bytes > record.code_bytes
            or record.deopts != 0
            or record.side_exits != 0
            or record.guard_failures != 0
            or record.interpreter_index_elements != 0
            or record.list_range_calls != 1
        ):
            raise CarrierError(f"native path admission failed for {kernel.name}")
        if record.record_hash != _record_hash(record):
            raise CarrierError(f"record seal mismatch for {kernel.name}")
        records.append(record)

    evidence_fields = lines[9].split("\t")
    if len(evidence_fields) != 2 or evidence_fields[0] != "evidence":
        raise CarrierError("invalid S4-WP3 evidence row")
    evidence_hash = _hash(evidence_fields[1], "candidate evidence")
    record_tuple = tuple(records)
    if evidence_hash != _evidence_hash(corpus_hash, record_tuple):
        raise CarrierError("S4-WP3 evidence seal mismatch")
    if lines[10] != "verification\tregenerated":
        raise CarrierError("S4-WP3 regenerative verification is missing")
    return Candidate(record_tuple, corpus_hash, evidence_hash, raw)


def _binary_path(value: Path) -> Path:
    binary = value.resolve()
    try:
        info = binary.stat()
    except OSError as error:
        raise CarrierError("S4-WP3 carrier binary is missing") from error
    if not stat.S_ISREG(info.st_mode) or not os.access(binary, os.X_OK):
        raise CarrierError("S4-WP3 carrier binary is not a regular executable")
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
        raise CarrierError("fixed-argv S4-WP3 process failed") from error


def replay(root: Path, admission: Admission, binary_value: Path) -> tuple[bytes, str]:
    root = root.resolve()
    binary = _binary_path(binary_value)
    candidates: list[Candidate] = []
    for _ in range(2):
        completed = _run(binary)
        if completed.returncode != 0 or completed.stderr != b"":
            raise CarrierError("S4-WP3 carrier failed or emitted diagnostics")
        candidates.append(parse_candidate(completed.stdout, root, admission.corpus))
    if candidates[0] != candidates[1]:
        raise CarrierError("S4-WP3 carrier replay is not deterministic")
    candidate = candidates[0]
    extras = [
        f"candidate-evidence\t{candidate.evidence_hash}",
        f"candidate-bytes\t{len(candidate.raw)}",
    ]
    extras.extend(
        f"kernel\t{record.ordinal:02}\t{record.name}\t{record.result}\t"
        f"{record.native_trace_hits}\t{record.record_hash}"
        for record in candidate.records
    )
    extras.append("replays\t2")
    return _report(admission.authority, "untimed-native-replay", extras)


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
        if args.report is not None:
            args.report.write_bytes(report)
        else:
            sys.stdout.buffer.write(report)
    except (CarrierError, wp2.ReferenceError, wp2.wp1.AuthorityError, OSError) as error:
        print(f"S4 native carrier rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
