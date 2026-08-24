#!/usr/bin/env python3
"""Validate and replay the untimed S4-WP2 C reference baselines."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import s4_benchmark_authority as wp1


BASELINES_MAGIC = "NAUX-S4-REFERENCE-BASELINES\t1"
AUTHORITY_MAGIC = "NAUX-S4-REFERENCE-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-REFERENCE-REPORT\t1"
BASELINES_DOMAIN = b"NAUX:s4-reference-baselines:manifest:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-reference-baselines:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-reference-baselines:report:v1\0"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
WP1_AUTHORITY_SEAL = "b23533c4e96ec9e3b66482e96b79fdeb5985c823ce012d827e69eb1c14a4b659"

BASELINE_METADATA = (
    ("policy-version", "1.0.0"),
    ("wp1-authority-seal", WP1_AUTHORITY_SEAL),
    ("claim-status", "not-admitted"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("dataset", "n16384-r50-v1"),
    ("language", "c17"),
    ("n", "16384"),
    ("reps", "50"),
    ("kernel-count", "4"),
    ("role-count", "2"),
)
EXPECTED_ROLES = (
    ("01", "c-generic", "runtime-n-and-reps"),
    ("02", "c-specialized", "static-n-and-reps"),
)
EXPECTED_FLAGS = (
    ("01", "common", "-D_POSIX_C_SOURCE=200809L"),
    ("02", "common", "-std=c17"),
    ("03", "common", "-O3"),
    ("04", "common", "-fno-fast-math"),
    ("05", "common", "-fno-lto"),
    ("06", "common", "-Wall"),
    ("07", "common", "-Wextra"),
    ("08", "common", "-Werror"),
    ("09", "common", "-Wpedantic"),
    ("10", "specialized", "-DNAUX_S4_SPECIALIZED=1"),
    ("11", "specialized", "-DNAUX_S4_N=16384"),
    ("12", "specialized", "-DNAUX_S4_REPS=50"),
)
EXPECTED_KERNELS = (
    ("01", "sum-dense", "6710476800", "benchmarks/s4/c/sum_dense.c"),
    ("02", "branch-mix", "-69189632", "benchmarks/s4/c/branch_mix.c"),
    ("03", "dot-product", "73294064435200", "benchmarks/s4/c/dot_product.c"),
    ("04", "list-update", "6730547200", "benchmarks/s4/c/list_update.c"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP2"),
    ("authority-id", "s4-reference-baselines-v1"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("claim-status", "not-admitted"),
    ("kernel-count", "4"),
    ("role-count", "2"),
    ("file-count", "11"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-reference-baselines.yml",
    "benchmarks/s4/c/baseline.h",
    "benchmarks/s4/c/branch_mix.c",
    "benchmarks/s4/c/dot_product.c",
    "benchmarks/s4/c/list_update.c",
    "benchmarks/s4/c/sum_dense.c",
    "distribution/s4-performance/BASELINES.tsv",
    "distribution/s4-performance/WP2-NONCLAIMS.md",
    "distribution/s4-performance/WP2-README.md",
    "scripts/s4_reference_baselines.py",
    "scripts/tests/test_s4_reference_baselines.py",
)
COMMON_FLAGS = tuple(row[2] for row in EXPECTED_FLAGS if row[1] == "common")
SPECIALIZED_FLAGS = tuple(row[2] for row in EXPECTED_FLAGS if row[1] == "specialized")
GENERIC_INVALID_ARGUMENTS = (
    (),
    ("0", "50"),
    ("+16384", "50"),
    ("016384", "50"),
    ("-1", "50"),
    ("184467440737095516160", "50"),
    ("16384", "0"),
    ("16384", "50", "extra"),
)


class ReferenceError(RuntimeError):
    """A fail-closed S4-WP2 reference-baseline error."""


@dataclass(frozen=True)
class Kernel:
    ordinal: str
    name: str
    expected: int
    source: str


@dataclass(frozen=True)
class Baselines:
    metadata: tuple[tuple[str, str], ...]
    roles: tuple[tuple[str, str, str], ...]
    flags: tuple[tuple[str, str, str], ...]
    kernels: tuple[Kernel, ...]
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
    baseline_component: tuple[str, str, str]
    parent: tuple[str, str, str]
    files: tuple[FileRecord, ...]
    seal: str


@dataclass(frozen=True)
class Admission:
    baselines: Baselines
    authority: Authority
    report: bytes
    report_root: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_canonical(
    path: Path, *, limit: int = 1_000_000, allow_blank: bool = False
) -> tuple[bytes, list[str]]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ReferenceError(f"cannot read S4-WP2 input: {path}") from error
    if len(raw) > limit:
        raise ReferenceError(f"S4-WP2 input exceeds size limit: {path}")
    if not raw.endswith(b"\n"):
        raise ReferenceError(f"S4-WP2 input must end with LF: {path}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReferenceError(f"S4-WP2 input must be UTF-8: {path}") from error
    if "\r" in text or "\x00" in text:
        raise ReferenceError(f"S4-WP2 input is not canonical LF text: {path}")
    lines = text.splitlines()
    if not allow_blank and any(not line for line in lines):
        raise ReferenceError(f"blank S4-WP2 rows are forbidden: {path}")
    return raw, lines


def _sealed_rows(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    _raw, lines = _read_canonical(path)
    if not lines or lines[0] != magic:
        raise ReferenceError(f"unsupported S4-WP2 schema: {path}")
    if len(lines) < 3 or not lines[-1].startswith("seal\t"):
        raise ReferenceError(f"missing terminal S4-WP2 seal: {path}")
    if any(line.startswith("seal\t") for line in lines[:-1]):
        raise ReferenceError(f"S4-WP2 seal must be terminal and unique: {path}")
    seal_fields = lines[-1].split("\t")
    if len(seal_fields) != 2 or not HASH_RE.fullmatch(seal_fields[1]):
        raise ReferenceError(f"invalid S4-WP2 seal: {path}")
    body = "".join(f"{line}\n" for line in lines[:-1]).encode()
    expected = _sha256(domain + body)
    if seal_fields[1] != expected:
        raise ReferenceError(f"S4-WP2 seal mismatch: {path}")
    return lines[1:-1], seal_fields[1]


def _safe_path(value: str, label: str) -> None:
    if not PATH_RE.fullmatch(value):
        raise ReferenceError(f"invalid path token for {label}")
    path = Path(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise ReferenceError(f"non-relative or traversing path for {label}")


def _metadata(
    lines: list[str], expected: tuple[tuple[str, str], ...], label: str
) -> tuple[tuple[str, str], ...]:
    if len(lines) < len(expected):
        raise ReferenceError(f"missing {label} metadata")
    rows: list[tuple[str, str]] = []
    for line in lines[: len(expected)]:
        fields = line.split("\t")
        if len(fields) != 3 or fields[0] != "meta":
            raise ReferenceError(f"invalid {label} metadata row")
        rows.append((fields[1], fields[2]))
    result = tuple(rows)
    if result != expected:
        raise ReferenceError(f"unexpected {label} metadata")
    return result


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
    raise ReferenceError(f"unknown S4-WP2 kernel: {name}")


def parse_baselines(path: Path) -> Baselines:
    lines, seal = _sealed_rows(path, BASELINES_MAGIC, BASELINES_DOMAIN)
    metadata = _metadata(lines, BASELINE_METADATA, "baseline")
    remaining = lines[len(BASELINE_METADATA) :]
    expected_count = len(EXPECTED_ROLES) + len(EXPECTED_FLAGS) + len(EXPECTED_KERNELS)
    if len(remaining) != expected_count:
        raise ReferenceError("unexpected baseline row count")

    role_rows = remaining[: len(EXPECTED_ROLES)]
    flag_start = len(EXPECTED_ROLES)
    flag_rows = remaining[flag_start : flag_start + len(EXPECTED_FLAGS)]
    kernel_rows = remaining[flag_start + len(EXPECTED_FLAGS) :]

    roles: list[tuple[str, str, str]] = []
    for line in role_rows:
        fields = line.split("\t")
        if len(fields) != 4 or fields[0] != "role":
            raise ReferenceError("invalid baseline role row")
        roles.append((fields[1], fields[2], fields[3]))
    if tuple(roles) != EXPECTED_ROLES:
        raise ReferenceError("unexpected baseline roles")

    flags: list[tuple[str, str, str]] = []
    for line in flag_rows:
        fields = line.split("\t")
        if len(fields) != 4 or fields[0] != "flag":
            raise ReferenceError("invalid baseline flag row")
        flags.append((fields[1], fields[2], fields[3]))
    if tuple(flags) != EXPECTED_FLAGS:
        raise ReferenceError("unexpected baseline compiler flags")

    kernels: list[Kernel] = []
    raw_kernels: list[tuple[str, str, str, str]] = []
    n = int(dict(metadata)["n"])
    reps = int(dict(metadata)["reps"])
    for line in kernel_rows:
        fields = line.split("\t")
        if len(fields) != 5 or fields[0] != "kernel":
            raise ReferenceError("invalid baseline kernel row")
        row = (fields[1], fields[2], fields[3], fields[4])
        raw_kernels.append(row)
        _safe_path(fields[4], "baseline source")
        try:
            expected = int(fields[3])
        except ValueError as error:
            raise ReferenceError("invalid baseline oracle") from error
        if expected != _oracle(fields[2], n, reps):
            raise ReferenceError(f"baseline oracle mismatch for {fields[2]}")
        kernels.append(Kernel(fields[1], fields[2], expected, fields[4]))
    if tuple(raw_kernels) != EXPECTED_KERNELS:
        raise ReferenceError("unexpected baseline kernel authority")
    return Baselines(metadata, tuple(roles), tuple(flags), tuple(kernels), seal)


def parse_authority(path: Path, baseline_seal: str) -> Authority:
    lines, seal = _sealed_rows(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    metadata = _metadata(lines, AUTHORITY_METADATA, "reference authority")
    remaining = lines[len(AUTHORITY_METADATA) :]
    if len(remaining) != 2 + len(EXPECTED_FILES):
        raise ReferenceError("unexpected reference authority row count")

    component_fields = remaining[0].split("\t")
    component = (
        "baselines",
        "distribution/s4-performance/BASELINES.tsv",
        baseline_seal,
    )
    if tuple(component_fields) != ("component", *component):
        raise ReferenceError("unexpected baseline component binding")

    parent_fields = remaining[1].split("\t")
    parent = (
        "benchmark-authority",
        "distribution/s4-performance/AUTHORITY.tsv",
        WP1_AUTHORITY_SEAL,
    )
    if tuple(parent_fields) != ("parent", *parent):
        raise ReferenceError("unexpected parent authority binding")

    files: list[FileRecord] = []
    for line in remaining[2:]:
        fields = line.split("\t")
        if len(fields) != 5 or fields[0] != "file":
            raise ReferenceError("invalid reference authority file row")
        if not MODE_RE.fullmatch(fields[1]):
            raise ReferenceError("invalid reference authority file mode")
        if not fields[2].isdigit() or int(fields[2]) > 2_000_000:
            raise ReferenceError("invalid reference authority file size")
        if not HASH_RE.fullmatch(fields[3]):
            raise ReferenceError("invalid reference authority file hash")
        _safe_path(fields[4], "reference authority file")
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise ReferenceError("unexpected reference authority file inventory")
    return Authority(metadata, component, parent, tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        try:
            info = path.lstat()
        except OSError as error:
            raise ReferenceError(f"missing bound S4-WP2 file: {record.path}") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ReferenceError(f"bound S4-WP2 path is not a regular file: {record.path}")
        actual_mode = stat.S_IFREG | stat.S_IMODE(info.st_mode)
        raw = path.read_bytes()
        if actual_mode != record.mode:
            raise ReferenceError(f"bound S4-WP2 mode mismatch: {record.path}")
        if len(raw) != record.size:
            raise ReferenceError(f"bound S4-WP2 size mismatch: {record.path}")
        if _sha256(raw) != record.sha256:
            raise ReferenceError(f"bound S4-WP2 hash mismatch: {record.path}")


def _verify_sources(root: Path, baselines: Baselines) -> None:
    header_path = root / "benchmarks/s4/c/baseline.h"
    _raw, header_lines = _read_canonical(header_path, allow_blank=True)
    header = "\n".join(header_lines)
    required_header = (
        "NAUX_S4_SPECIALIZED",
        "NAUX_S4_N",
        "NAUX_S4_REPS",
        "naux_s4_parse_positive_size",
        "naux_s4_allocate",
        "naux_s4_emit",
        "specialized-role-accepts-no-dataset-arguments",
        "expected-positive-decimal-n-and-reps",
        "NAUX-S4-BASELINE\\t1",
    )
    if any(token not in header for token in required_header):
        raise ReferenceError("shared C baseline boundary is incomplete")

    per_kernel_tokens = {
        "sum-dense": ("sum += values[i];",),
        "branch-mix": ("state += 17;", "state -= 97;", "state < 48"),
        "dot-product": ("sum += value * value;",),
        "list-update": ("sum += value;", "values[i] = value + 1.0;"),
    }
    forbidden = ("clock_gettime", "now_ns", "median", "p95", "cv_pct")
    for kernel in baselines.kernels:
        path = root / kernel.source
        _source_raw, source_lines = _read_canonical(path, allow_blank=True)
        source = "\n".join(source_lines)
        required = (
            f'#define NAUX_S4_KERNEL_NAME "{kernel.name}"',
            '#include "baseline.h"',
            "int main(int argc, char **argv)",
            "naux_s4_dataset(argc, argv, &n, &reps)",
            "naux_s4_allocate(n)",
            "free(values);",
            "naux_s4_emit(n, reps, total)",
            "for (size_t repeat = 0; repeat < reps; repeat++)",
        ) + per_kernel_tokens[kernel.name]
        if any(token not in source for token in required):
            raise ReferenceError(f"C baseline structure mismatch for {kernel.name}")
        if str(kernel.expected) in source or any(token in source for token in forbidden):
            raise ReferenceError(f"closed-form or timing token in C baseline for {kernel.name}")


def _report(admission: tuple[Baselines, Authority], mode: str, extra: list[str]) -> tuple[bytes, str]:
    baselines, authority = admission
    lines = [
        REPORT_MAGIC,
        "claim-status\tnot-admitted",
        f"mode\t{mode}",
        f"parent-authority-seal\t{WP1_AUTHORITY_SEAL}",
        f"baseline-seal\t{baselines.seal}",
        f"authority-seal\t{authority.seal}",
        f"files\t{len(authority.files)}",
        f"roles\t{len(baselines.roles)}",
        f"kernels\t{len(baselines.kernels)}",
    ]
    lines.extend(extra)
    body = "".join(f"{line}\n" for line in lines).encode()
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve()
    parent = wp1.validate(root)
    if parent.authority.seal != WP1_AUTHORITY_SEAL:
        raise ReferenceError("accepted parent benchmark authority drifted")
    baselines = parse_baselines(root / "distribution/s4-performance/BASELINES.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP2-AUTHORITY.tsv", baselines.seal
    )
    _verify_files(root, authority)
    _verify_sources(root, baselines)
    extras = [
        f"oracle\t{kernel.ordinal}\t{kernel.name}\t{kernel.expected}"
        for kernel in baselines.kernels
    ]
    report, report_root = _report((baselines, authority), "static", extras)
    return Admission(baselines, authority, report, report_root)


def _compiler_path(command: str) -> Path:
    located = shutil.which(command)
    if located is None:
        raise ReferenceError("C compiler was not found")
    compiler = Path(located).resolve()
    try:
        info = compiler.stat()
    except OSError as error:
        raise ReferenceError("cannot inspect C compiler") from error
    if not stat.S_ISREG(info.st_mode) or not os.access(compiler, os.X_OK):
        raise ReferenceError("C compiler is not a regular executable")
    return compiler


def _run(argv: list[str], *, timeout: int) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    try:
        return subprocess.run(
            argv,
            input=b"",
            capture_output=True,
            check=False,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReferenceError("fixed-argv S4-WP2 process failed") from error


def replay_parity(root: Path, admission: Admission, cc: str) -> tuple[bytes, str]:
    root = root.resolve()
    compiler = _compiler_path(cc)
    metadata = dict(admission.baselines.metadata)
    n = metadata["n"]
    reps = metadata["reps"]
    parity_rows: list[str] = []
    negative_runs = 0

    with tempfile.TemporaryDirectory(prefix="naux-s4-reference-") as directory_name:
        directory = Path(directory_name)
        for kernel in admission.baselines.kernels:
            source = root / kernel.source
            binaries: dict[str, Path] = {}
            for role, role_flags in (
                ("c-generic", ()),
                ("c-specialized", SPECIALIZED_FLAGS),
            ):
                binary = directory / f"{kernel.ordinal}-{role}"
                argv = [
                    str(compiler),
                    *COMMON_FLAGS,
                    *role_flags,
                    str(source),
                    "-o",
                    str(binary),
                ]
                compiled = _run(argv, timeout=60)
                if compiled.returncode != 0 or compiled.stdout != b"" or compiled.stderr != b"":
                    raise ReferenceError(f"C compilation failed or emitted diagnostics for {kernel.name}/{role}")
                binaries[role] = binary

            for role, argv_tail in (
                ("c-generic", (n, reps)),
                ("c-specialized", ()),
            ):
                expected = (
                    f"NAUX-S4-BASELINE\t1\t{kernel.name}\t{role}\t{n}\t{reps}\t"
                    f"{kernel.expected}\n"
                ).encode()
                completed = _run([str(binaries[role]), *argv_tail], timeout=15)
                if completed.returncode != 0 or completed.stdout != expected or completed.stderr != b"":
                    raise ReferenceError(f"C parity mismatch for {kernel.name}/{role}")
                parity_rows.append(
                    f"parity\t{kernel.ordinal}\t{kernel.name}\t{role}\t{kernel.expected}"
                )

            generic_error = b"error\texpected-positive-decimal-n-and-reps\n"
            for invalid in GENERIC_INVALID_ARGUMENTS:
                completed = _run([str(binaries["c-generic"]), *invalid], timeout=15)
                if completed.returncode != 64 or completed.stdout != b"" or completed.stderr != generic_error:
                    raise ReferenceError(f"generic argument rejection drifted for {kernel.name}")
                negative_runs += 1
            specialized_error = b"error\tspecialized-role-accepts-no-dataset-arguments\n"
            completed = _run(
                [str(binaries["c-specialized"]), n, reps], timeout=15
            )
            if (
                completed.returncode != 64
                or completed.stdout != b""
                or completed.stderr != specialized_error
            ):
                raise ReferenceError(f"specialized argument rejection drifted for {kernel.name}")
            negative_runs += 1

    extras = [
        f"parity-runs\t{len(parity_rows)}",
        f"negative-runs\t{negative_runs}",
        *parity_rows,
    ]
    return _report((admission.baselines, admission.authority), "untimed-parity", extras)


def _default_root() -> Path:
    return Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=_default_root())
    parser.add_argument("--cc")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        admission = validate(args.root)
        report = admission.report
        if args.cc is not None:
            report, _root = replay_parity(args.root, admission, args.cc)
        if args.report is not None:
            args.report.write_bytes(report)
        else:
            sys.stdout.buffer.write(report)
    except (ReferenceError, wp1.AuthorityError, OSError) as error:
        print(f"S4 reference baselines rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
