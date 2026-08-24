#!/usr/bin/env python3
"""Validate the sealed, pre-measurement Scope-4 benchmark authority."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


CORPUS_MAGIC = "NAUX-S4-BENCHMARK-CORPUS\t1"
PROTOCOL_MAGIC = "NAUX-S4-BENCHMARK-PROTOCOL\t1"
AUTHORITY_MAGIC = "NAUX-S4-BENCHMARK-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-BENCHMARK-AUTHORITY-REPORT\t1"
CORPUS_DOMAIN = b"NAUX:s4-benchmark:corpus:v1\0"
PROTOCOL_DOMAIN = b"NAUX:s4-benchmark:protocol:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-benchmark:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-benchmark:authority-report:v1\0"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
DECIMAL_RE = re.compile(r"-?[0-9]+\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
MAX_EXACT_BINARY64_INTEGER = 1 << 53

CORPUS_METADATA = (
    ("dataset", "n65536-r50-v1"),
    ("numeric-domain", "binary64-exact-integer-v1"),
    ("kernel-count", "4"),
)
EXPECTED_KERNELS = (
    (
        "01",
        "sum-dense",
        "throughput",
        "dense-iteration",
        "65536",
        "50",
        "107372544000",
        "benchmarks/s4/naux/sum_dense.nx",
        "benchmarks/c/bench_sum_dense.c",
        "benchmarks/rust/src/bin/bench_sum_dense.rs",
    ),
    (
        "02",
        "branch-mix",
        "control-flow",
        "stateful-branch",
        "65536",
        "50",
        "-1106833456",
        "benchmarks/s4/naux/branch_mix.nx",
        "benchmarks/c/bench_branch_mix.c",
        "benchmarks/rust/src/bin/bench_branch_mix.rs",
    ),
    (
        "03",
        "dot-product",
        "arithmetic",
        "quadratic-reduction",
        "65536",
        "50",
        "4691142238208000",
        "benchmarks/s4/naux/dot_product.nx",
        "benchmarks/c/bench_dot_product.c",
        "benchmarks/rust/src/bin/bench_dot_product.rs",
    ),
    (
        "04",
        "list-update",
        "allocation-mutation",
        "stateful-list-update",
        "65536",
        "50",
        "107452825600",
        "benchmarks/s4/naux/list_update.nx",
        "benchmarks/c/bench_list_update.c",
        "benchmarks/rust/src/bin/bench_list_update.rs",
    ),
)
PROTOCOL_METADATA = (
    ("policy-version", "1.0.0"),
    ("claim-status", "not-admitted"),
    ("minimum-warmup-ms", "100"),
    ("measured-samples", "30"),
    ("maximum-cv-percent", "5"),
    ("outlier-policy", "report-all-no-hidden-drop"),
    ("runtime-region", "allocation-initialization-kernel-checksum-teardown"),
    ("separate-costs", "compile-specialize-startup-runtime-memory-code-size"),
    ("fast-math", "forbidden"),
    ("closed-form-replacement", "forbidden"),
    ("residual-max-specialized-ratio", "1.10"),
    ("residual-min-generic-speedup", "1.25"),
    ("result-requirements", "raw-samples-toolchains-flags-host-fingerprint"),
)
EXPECTED_ROLES = (
    ("01", "naux-residual", "comparison", "required", "static-n-and-reps"),
    ("02", "c-generic", "baseline", "required", "runtime-n-and-reps"),
    ("03", "c-specialized", "baseline", "required", "static-n-and-reps"),
    ("04", "rust-generic", "supporting", "optional", "runtime-n-and-reps"),
    ("05", "rust-specialized", "supporting", "optional", "static-n-and-reps"),
)
EXPECTED_METRICS = (
    ("01", "runtime-ns", "ns", "median", "required", "runtime-region"),
    ("02", "compile-ns", "ns", "median", "required", "compiler-only"),
    ("03", "specialization-ns", "ns", "median", "required", "specializer-only"),
    ("04", "startup-ns", "ns", "median", "required", "process-start-to-ready"),
    ("05", "peak-rss-bytes", "bytes", "maximum", "required", "whole-process"),
    ("06", "code-size-bytes", "bytes", "exact", "required", "emitted-text-and-rodata"),
    ("07", "cycles", "count", "median", "supporting", "runtime-region"),
    ("08", "instructions", "count", "median", "supporting", "runtime-region"),
    ("09", "branches", "count", "median", "supporting", "runtime-region"),
    ("10", "branch-misses", "count", "median", "supporting", "runtime-region"),
    ("11", "cache-misses", "count", "median", "supporting", "runtime-region"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP1"),
    ("authority-id", "s4-benchmark-authority-v1"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("claim-status", "not-admitted"),
    ("kernel-count", "4"),
    ("file-count", "22"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-authority.yml",
    "PERF_CONTRACT.md",
    "benchmarks/c/bench_branch_mix.c",
    "benchmarks/c/bench_dot_product.c",
    "benchmarks/c/bench_list_update.c",
    "benchmarks/c/bench_sum_dense.c",
    "benchmarks/rust/Cargo.lock",
    "benchmarks/rust/Cargo.toml",
    "benchmarks/rust/src/bin/bench_branch_mix.rs",
    "benchmarks/rust/src/bin/bench_dot_product.rs",
    "benchmarks/rust/src/bin/bench_list_update.rs",
    "benchmarks/rust/src/bin/bench_sum_dense.rs",
    "benchmarks/s4/naux/branch_mix.nx",
    "benchmarks/s4/naux/dot_product.nx",
    "benchmarks/s4/naux/list_update.nx",
    "benchmarks/s4/naux/sum_dense.nx",
    "distribution/s4-performance/CORPUS.tsv",
    "distribution/s4-performance/NONCLAIMS.md",
    "distribution/s4-performance/PROTOCOL.tsv",
    "distribution/s4-performance/README.md",
    "scripts/s4_benchmark_authority.py",
    "scripts/tests/test_s4_benchmark_authority.py",
)


class AuthorityError(RuntimeError):
    """A fail-closed Scope-4 benchmark-authority error."""


@dataclass(frozen=True)
class Kernel:
    ordinal: str
    name: str
    category: str
    specialization: str
    n: int
    reps: int
    expected: int
    naux_source: str
    c_source: str
    rust_source: str


@dataclass(frozen=True)
class Corpus:
    metadata: tuple[tuple[str, str], ...]
    kernels: tuple[Kernel, ...]
    seal: str


@dataclass(frozen=True)
class Protocol:
    metadata: tuple[tuple[str, str], ...]
    roles: tuple[tuple[str, ...], ...]
    metrics: tuple[tuple[str, ...], ...]
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
    components: tuple[tuple[str, str, str], ...]
    files: tuple[FileRecord, ...]
    seal: str


@dataclass(frozen=True)
class Admission:
    corpus: Corpus
    protocol: Protocol
    authority: Authority
    report: bytes
    report_root: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_lines(
    path: Path,
    *,
    limit: int = 1_000_000,
    allow_blank: bool = False,
) -> tuple[bytes, list[str]]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise AuthorityError(f"cannot read authority input: {path}") from error
    if len(raw) > limit:
        raise AuthorityError(f"authority input exceeds size limit: {path}")
    if not raw.endswith(b"\n"):
        raise AuthorityError(f"authority input must end with LF: {path}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AuthorityError(f"authority input must be UTF-8: {path}") from error
    if "\r" in text or "\x00" in text:
        raise AuthorityError(f"authority input is not canonical LF text: {path}")
    lines = text.splitlines()
    if not allow_blank and any(not line for line in lines):
        raise AuthorityError(f"blank authority rows are forbidden: {path}")
    return raw, lines


def _sealed_lines(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    _raw, lines = _read_lines(path)
    if not lines or lines[0] != magic:
        raise AuthorityError(f"unsupported authority schema: {path}")
    if len(lines) < 3 or not lines[-1].startswith("seal\t"):
        raise AuthorityError(f"missing terminal authority seal: {path}")
    if any(line.startswith("seal\t") for line in lines[:-1]):
        raise AuthorityError(f"authority seal must be terminal and unique: {path}")
    seal_fields = lines[-1].split("\t")
    if len(seal_fields) != 2 or not HASH_RE.fullmatch(seal_fields[1]):
        raise AuthorityError(f"invalid authority seal: {path}")
    body = "".join(f"{line}\n" for line in lines[:-1]).encode()
    expected = _sha256(domain + body)
    if seal_fields[1] != expected:
        raise AuthorityError(f"authority seal mismatch: {path}")
    return lines[1:-1], seal_fields[1]


def _safe_token(value: str, field: str) -> None:
    if not TOKEN_RE.fullmatch(value):
        raise AuthorityError(f"invalid data token for {field}")


def _safe_path(value: str, field: str) -> None:
    if not PATH_RE.fullmatch(value):
        raise AuthorityError(f"invalid path token for {field}")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise AuthorityError(f"non-relative or traversing path for {field}")


def _ordered_metadata(lines: list[str], count: int, expected: tuple[tuple[str, str], ...], label: str) -> tuple[tuple[str, str], ...]:
    if len(lines) < count:
        raise AuthorityError(f"missing {label} metadata")
    result: list[tuple[str, str]] = []
    for line in lines[:count]:
        fields = line.split("\t")
        if len(fields) != 3 or fields[0] != "meta":
            raise AuthorityError(f"invalid {label} metadata row")
        _safe_token(fields[1], f"{label} metadata key")
        result.append((fields[1], fields[2]))
    metadata = tuple(result)
    if metadata != expected:
        raise AuthorityError(f"unexpected {label} metadata")
    return metadata


def _oracle(name: str, n: int, reps: int) -> int:
    if name == "sum-dense":
        return reps * n * (n - 1) // 2
    if name == "dot-product":
        return reps * n * (n - 1) * (2 * n - 1) // 6
    if name == "list-update":
        return reps * n * (n - 1) // 2 + n * reps * (reps - 1) // 2
    if name == "branch-mix":
        state = 0
        total = 0
        for _ in range(reps):
            for index in range(n):
                state = (state + 17) % 97
                total += index if state < 48 else -index
        return total
    raise AuthorityError(f"unknown kernel oracle: {name}")


def parse_corpus(path: Path) -> Corpus:
    lines, seal = _sealed_lines(path, CORPUS_MAGIC, CORPUS_DOMAIN)
    metadata = _ordered_metadata(lines, len(CORPUS_METADATA), CORPUS_METADATA, "corpus")
    kernel_lines = lines[len(CORPUS_METADATA) :]
    if len(kernel_lines) != len(EXPECTED_KERNELS):
        raise AuthorityError("unexpected corpus kernel count")
    raw_rows: list[tuple[str, ...]] = []
    kernels: list[Kernel] = []
    for line in kernel_lines:
        fields = line.split("\t")
        if len(fields) != 11 or fields[0] != "kernel":
            raise AuthorityError("invalid corpus kernel row")
        row = tuple(fields[1:])
        raw_rows.append(row)
        for index, value in enumerate(row[:4]):
            _safe_token(value, f"kernel field {index}")
        for value in row[7:]:
            _safe_path(value, "kernel source")
        if not DECIMAL_RE.fullmatch(row[4]) or not DECIMAL_RE.fullmatch(row[5]) or not DECIMAL_RE.fullmatch(row[6]):
            raise AuthorityError("invalid corpus integer")
        n, reps, expected = int(row[4]), int(row[5]), int(row[6])
        if n <= 0 or reps <= 0:
            raise AuthorityError("corpus dimensions must be positive")
        computed = _oracle(row[1], n, reps)
        if expected != computed:
            raise AuthorityError(f"semantic oracle mismatch for {row[1]}")
        if abs(computed) >= MAX_EXACT_BINARY64_INTEGER:
            raise AuthorityError(f"oracle exceeds exact binary64 integer range for {row[1]}")
        kernels.append(Kernel(row[0], row[1], row[2], row[3], n, reps, expected, row[7], row[8], row[9]))
    if tuple(raw_rows) != EXPECTED_KERNELS:
        raise AuthorityError("unexpected corpus kernel authority")
    return Corpus(metadata, tuple(kernels), seal)


def parse_protocol(path: Path) -> Protocol:
    lines, seal = _sealed_lines(path, PROTOCOL_MAGIC, PROTOCOL_DOMAIN)
    metadata = _ordered_metadata(lines, len(PROTOCOL_METADATA), PROTOCOL_METADATA, "protocol")
    remaining = lines[len(PROTOCOL_METADATA) :]
    roles: list[tuple[str, ...]] = []
    metrics: list[tuple[str, ...]] = []
    for line in remaining:
        fields = line.split("\t")
        if fields[0] == "role":
            if len(fields) != 6 or metrics:
                raise AuthorityError("invalid or reordered protocol role row")
            row = tuple(fields[1:])
            for index, value in enumerate(row):
                _safe_token(value, f"role field {index}")
            roles.append(row)
        elif fields[0] == "metric":
            if len(fields) != 7:
                raise AuthorityError("invalid protocol metric row")
            row = tuple(fields[1:])
            for index, value in enumerate(row):
                _safe_token(value, f"metric field {index}")
            metrics.append(row)
        else:
            raise AuthorityError("unknown protocol row")
    if tuple(roles) != EXPECTED_ROLES:
        raise AuthorityError("unexpected protocol roles")
    if tuple(metrics) != EXPECTED_METRICS:
        raise AuthorityError("unexpected protocol metrics")
    return Protocol(metadata, tuple(roles), tuple(metrics), seal)


def parse_authority(path: Path, corpus_seal: str, protocol_seal: str) -> Authority:
    lines, seal = _sealed_lines(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    metadata = _ordered_metadata(lines, len(AUTHORITY_METADATA), AUTHORITY_METADATA, "authority")
    remaining = lines[len(AUTHORITY_METADATA) :]
    if len(remaining) != 2 + len(EXPECTED_FILES):
        raise AuthorityError("unexpected authority row count")
    components: list[tuple[str, str, str]] = []
    for line in remaining[:2]:
        fields = line.split("\t")
        if len(fields) != 4 or fields[0] != "component":
            raise AuthorityError("invalid authority component row")
        _safe_token(fields[1], "component name")
        _safe_path(fields[2], "component path")
        if not HASH_RE.fullmatch(fields[3]):
            raise AuthorityError("invalid component seal")
        components.append((fields[1], fields[2], fields[3]))
    expected_components = (
        ("corpus", "distribution/s4-performance/CORPUS.tsv", corpus_seal),
        ("protocol", "distribution/s4-performance/PROTOCOL.tsv", protocol_seal),
    )
    if tuple(components) != expected_components:
        raise AuthorityError("unexpected authority component binding")
    files: list[FileRecord] = []
    for line in remaining[2:]:
        fields = line.split("\t")
        if len(fields) != 5 or fields[0] != "file":
            raise AuthorityError("invalid authority file row")
        if not MODE_RE.fullmatch(fields[1]):
            raise AuthorityError("invalid authority file mode")
        if not fields[2].isdigit() or int(fields[2]) > 10_000_000:
            raise AuthorityError("invalid authority file size")
        if not HASH_RE.fullmatch(fields[3]):
            raise AuthorityError("invalid authority file hash")
        _safe_path(fields[4], "authority file")
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise AuthorityError("unexpected authority file inventory")
    return Authority(metadata, tuple(components), tuple(files), seal)


def _verify_source_dimensions(root: Path, kernel: Kernel) -> None:
    path = root / kernel.naux_source
    _raw, lines = _read_lines(path, allow_blank=True)
    n_values = [line.strip().split(" = ", 1)[1] for line in lines if line.strip().startswith("$n = ")]
    reps_values = [line.strip().split(" = ", 1)[1] for line in lines if line.strip().startswith("$reps = ")]
    if n_values != [str(kernel.n)] or reps_values != [str(kernel.reps)]:
        raise AuthorityError(f"NAUX source dimensions disagree for {kernel.name}")


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        try:
            info = path.lstat()
        except OSError as error:
            raise AuthorityError(f"missing bound authority file: {record.path}") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise AuthorityError(f"bound authority path is not a regular file: {record.path}")
        actual_mode = stat.S_IFREG | stat.S_IMODE(info.st_mode)
        raw = path.read_bytes()
        if actual_mode != record.mode:
            raise AuthorityError(f"bound authority mode mismatch: {record.path}")
        if len(raw) != record.size:
            raise AuthorityError(f"bound authority size mismatch: {record.path}")
        if _sha256(raw) != record.sha256:
            raise AuthorityError(f"bound authority hash mismatch: {record.path}")


def validate(root: Path) -> Admission:
    root = root.resolve()
    directory = root / "distribution/s4-performance"
    corpus = parse_corpus(directory / "CORPUS.tsv")
    protocol = parse_protocol(directory / "PROTOCOL.tsv")
    authority = parse_authority(directory / "AUTHORITY.tsv", corpus.seal, protocol.seal)
    _verify_files(root, authority)
    for kernel in corpus.kernels:
        _verify_source_dimensions(root, kernel)
    report_lines = [
        REPORT_MAGIC,
        "claim-status\tnot-admitted",
        f"authority-seal\t{authority.seal}",
        f"corpus-seal\t{corpus.seal}",
        f"protocol-seal\t{protocol.seal}",
        f"files\t{len(authority.files)}",
    ]
    for kernel in corpus.kernels:
        report_lines.append(f"oracle\t{kernel.ordinal}\t{kernel.name}\t{kernel.expected}")
    body = "".join(f"{line}\n" for line in report_lines).encode()
    report_root = _sha256(REPORT_DOMAIN + body)
    report = body + f"report-root\t{report_root}\n".encode()
    return Admission(corpus, protocol, authority, report, report_root)


def _default_root() -> Path:
    return Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=_default_root())
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        admission = validate(args.root)
        if args.report is not None:
            args.report.write_bytes(admission.report)
        else:
            sys.stdout.buffer.write(admission.report)
    except (AuthorityError, OSError) as error:
        print(f"S4 benchmark authority rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
