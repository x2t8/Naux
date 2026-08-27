#!/usr/bin/env python3
"""Replay and compile-audit the non-executing S4-WP7B C timing carriers."""

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

import s4_measurement_evidence as wp7a
import s4_reference_baselines as wp2
import s4_residual_timing as wp7b_naux


CONTRACT_MAGIC = "NAUX-S4-C-TIMING-CARRIER-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-C-TIMING-CARRIER-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-C-TIMING-CARRIER-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-c-timing-carrier:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-c-timing-carrier:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-c-timing-carrier:report:v1\0"
WP2_AUTHORITY_SEAL = "0361c1e0d90bc3ba8d9a1e0bead7466bd71be3e3a723d605606730144ae7db6a"
WP7A_AUTHORITY_SEAL = "a3a838a64dcffcca4cc4586eba304737ab66a56e11ff2c4616196f4f22de1e67"
WP7B_NAUX_AUTHORITY_SEAL = "61e42d60f76b5bbb322c870a53beb2b357ab0f22b660b971baa0f0ed3f0cf337"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-baseline-authority", WP2_AUTHORITY_SEAL),
    ("sibling-naux-carrier-authority", WP7B_NAUX_AUTHORITY_SEAL),
    ("parent-evidence-law-authority", WP7A_AUTHORITY_SEAL),
    ("status", "c-timing-carriers-structurally-admitted"),
    ("execution-status", "forbidden"),
    ("claim-status", "not-admitted"),
    ("clock-source", "clock-monotonic-raw-direct-syscall"),
    ("clock-reads", "2"),
    ("clock-placement", "before-allocation-after-checksum-validation-and-teardown"),
    ("derivation", "exact-mechanical-wp2-source-wrapper"),
    ("result-protocol", "fixed-le56-v1"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("language", "c17"),
    ("kernel-count", "4"),
    ("role-count", "2"),
)
EXPECTED_ROLES = (
    ("01", "c-generic", "runtime-n-and-reps", "2"),
    ("02", "c-specialized", "static-n-and-reps", "3"),
)
EXPECTED_CLOSURES = (
    ("01", "c-generic-in-role-timing-carrier-unavailable", "closed", "wp7b-c-exact-source-derivation"),
    ("02", "c-specialized-in-role-timing-carrier-unavailable", "closed", "wp7b-c-exact-source-derivation"),
)
EXPECTED_BLOCKERS = (
    ("01", "retained-controlled-host-attestation-unavailable"),
    ("02", "measurement-runner-unavailable"),
    ("03", "raw-measurement-evidence-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP7B"),
    ("authority-id", "s4-c-timing-carriers-v1"),
    ("status", "c-timing-carriers-structurally-admitted"),
    ("execution-status", "forbidden"),
    ("claim-status", "not-admitted"),
    ("file-count", "11"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-c-timing-carriers.yml",
    "benchmarks/s4/c/timing_carrier.h",
    "benchmarks/s4/c/timing/branch_mix.c",
    "benchmarks/s4/c/timing/dot_product.c",
    "benchmarks/s4/c/timing/list_update.c",
    "benchmarks/s4/c/timing/sum_dense.c",
    "distribution/s4-performance/C-TIMING-CARRIER.tsv",
    "distribution/s4-performance/C-TIMING-NONCLAIMS.md",
    "distribution/s4-performance/C-TIMING-README.md",
    "scripts/s4_c_timing_carriers.py",
    "scripts/tests/test_s4_c_timing_carriers.py",
)
COMMON_FLAGS = wp2.COMMON_FLAGS
SPECIALIZED_FLAGS = wp2.SPECIALIZED_FLAGS


class CCarrierError(RuntimeError):
    """A fail-closed S4-WP7B C-carrier error."""


@dataclass(frozen=True)
class KernelRecord:
    ordinal: int
    name: str
    oracle: int
    parent_path: str
    parent_hash: str
    derived_path: str
    derived_hash: str


@dataclass(frozen=True)
class Contract:
    kernels: tuple[KernelRecord, ...]
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


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(path: Path, label: str, maximum: int = 2_000_000) -> tuple[bytes, list[str]]:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise CCarrierError(f"cannot read {label}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CCarrierError(f"{label} is not a regular file")
    if not raw or len(raw) > maximum or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise CCarrierError(f"{label} is not canonical LF text")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CCarrierError(f"{label} is not UTF-8") from error
    return raw, text.splitlines()


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    _raw, lines = _canonical(path, path.name)
    if not lines or lines[0] != magic or len(lines) < 3:
        raise CCarrierError(f"{path.name} magic or shape drifted")
    if any(line.startswith("seal\t") for line in lines[:-1]):
        raise CCarrierError(f"{path.name} contains a non-terminal seal")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or fields[0] != "seal" or not HASH_RE.fullmatch(fields[1]):
        raise CCarrierError(f"{path.name} seal row is malformed")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if _sha256(domain + body) != fields[1]:
        raise CCarrierError(f"{path.name} seal mismatch")
    return lines[1:-1], fields[1]


def _safe_path(value: str) -> None:
    if not PATH_RE.fullmatch(value):
        raise CCarrierError("carrier path token is malformed")
    path = Path(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise CCarrierError("carrier path is absolute or traversing")


def parse_contract(path: Path) -> Contract:
    lines, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    index = 0
    metadata: list[tuple[str, str]] = []
    while index < len(lines) and lines[index].startswith("meta\t"):
        fields = lines[index].split("\t")
        if len(fields) != 3:
            raise CCarrierError("contract metadata is malformed")
        metadata.append((fields[1], fields[2]))
        index += 1
    if tuple(metadata) != CONTRACT_METADATA:
        raise CCarrierError("contract metadata drifted")

    roles: list[tuple[str, str, str, str]] = []
    while index < len(lines) and lines[index].startswith("role\t"):
        fields = lines[index].split("\t")
        if len(fields) != 5:
            raise CCarrierError("contract role row is malformed")
        roles.append(tuple(fields[1:]))
        index += 1
    if tuple(roles) != EXPECTED_ROLES:
        raise CCarrierError("contract role order or identity drifted")

    kernels: list[KernelRecord] = []
    while index < len(lines) and lines[index].startswith("kernel\t"):
        fields = lines[index].split("\t")
        if (
            len(fields) != 8
            or fields[1] != f"{len(kernels) + 1:02}"
            or not INT_RE.fullmatch(fields[3])
            or not HASH_RE.fullmatch(fields[5])
            or not HASH_RE.fullmatch(fields[7])
        ):
            raise CCarrierError("contract kernel row is malformed")
        _safe_path(fields[4])
        _safe_path(fields[6])
        kernels.append(
            KernelRecord(
                int(fields[1]), fields[2], int(fields[3]), fields[4], fields[5],
                fields[6], fields[7]
            )
        )
        index += 1
    expected_kernels = tuple(
        (int(ordinal), name, int(oracle), source)
        for ordinal, name, oracle, source in wp2.EXPECTED_KERNELS
    )
    observed_kernels = tuple(
        (record.ordinal, record.name, record.oracle, record.parent_path)
        for record in kernels
    )
    if observed_kernels != expected_kernels:
        raise CCarrierError("contract kernel parent identity drifted")
    if tuple(record.derived_path for record in kernels) != tuple(
        f"benchmarks/s4/c/timing/{Path(record.parent_path).name}" for record in kernels
    ):
        raise CCarrierError("contract derived-source path drifted")

    closures: list[tuple[str, str, str, str]] = []
    while index < len(lines) and lines[index].startswith("closure\t"):
        fields = lines[index].split("\t")
        if len(fields) != 5:
            raise CCarrierError("contract closure row is malformed")
        closures.append(tuple(fields[1:]))
        index += 1
    if tuple(closures) != EXPECTED_CLOSURES:
        raise CCarrierError("contract closures drifted")

    blockers: list[tuple[str, str]] = []
    while index < len(lines) and lines[index].startswith("blocker\t"):
        fields = lines[index].split("\t")
        if len(fields) != 3:
            raise CCarrierError("contract blocker row is malformed")
        blockers.append(tuple(fields[1:]))
        index += 1
    if tuple(blockers) != EXPECTED_BLOCKERS or index != len(lines):
        raise CCarrierError("contract blockers or terminal shape drifted")
    return Contract(tuple(kernels), seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    index = 0
    metadata: list[tuple[str, str]] = []
    while index < len(lines) and lines[index].startswith("meta\t"):
        fields = lines[index].split("\t")
        if len(fields) != 3:
            raise CCarrierError("authority metadata is malformed")
        metadata.append((fields[1], fields[2]))
        index += 1
    if tuple(metadata) != AUTHORITY_METADATA:
        raise CCarrierError("authority metadata drifted")
    expected_bindings = (
        ("component", "c-timing-carrier", "distribution/s4-performance/C-TIMING-CARRIER.tsv", contract_seal),
        ("parent", "baseline-authority", "distribution/s4-performance/WP2-AUTHORITY.tsv", WP2_AUTHORITY_SEAL),
        ("sibling", "naux-carrier-authority", "distribution/s4-performance/WP7B-AUTHORITY.tsv", WP7B_NAUX_AUTHORITY_SEAL),
        ("parent", "evidence-law-authority", "distribution/s4-performance/WP7A-AUTHORITY.tsv", WP7A_AUTHORITY_SEAL),
    )
    bindings: list[tuple[str, ...]] = []
    for _expected in expected_bindings:
        if index >= len(lines):
            raise CCarrierError("authority binding is missing")
        bindings.append(tuple(lines[index].split("\t")))
        index += 1
    if tuple(bindings) != expected_bindings:
        raise CCarrierError("authority binding drifted")

    files: list[FileRecord] = []
    while index < len(lines):
        fields = lines[index].split("\t")
        if (
            len(fields) != 6
            or fields[0] != "file"
            or not MODE_RE.fullmatch(fields[1])
            or not fields[2].isdigit()
            or int(fields[2]) > 2_000_000
            or not HASH_RE.fullmatch(fields[3])
            or fields[5] != "c-timing-carrier"
        ):
            raise CCarrierError("authority file row is malformed")
        _safe_path(fields[4])
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
        index += 1
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise CCarrierError("authority file inventory drifted")
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        try:
            metadata = path.lstat()
            raw = path.read_bytes()
        except OSError as error:
            raise CCarrierError(f"cannot inspect bound file {record.path}") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise CCarrierError(f"bound path is not a regular file: {record.path}")
        mode = stat.S_IFREG | stat.S_IMODE(metadata.st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise CCarrierError(f"bound file identity drifted: {record.path}")


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    if source.count(old) != 1:
        raise CCarrierError(f"WP2 source anchor drifted: {label}")
    return source.replace(old, new, 1)


def _oracle_define(oracle: int) -> str:
    if oracle < 0:
        return f"(-INT64_C({-oracle}))"
    return f"INT64_C({oracle})"


def derive_source(parent: bytes, record: KernelRecord) -> bytes:
    try:
        source = parent.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CCarrierError("WP2 parent source is not UTF-8") from error
    header = f'#define NAUX_S4_KERNEL_NAME "{record.name}"\n#include "baseline.h"\n'
    derived_header = (
        f'#define NAUX_S4_KERNEL_NAME "{record.name}"\n'
        f"#define NAUX_S4_KERNEL_ORDINAL {record.ordinal}\n"
        f"#define NAUX_S4_ORACLE {_oracle_define(record.oracle)}\n"
        '#include "../baseline.h"\n'
        '#include "../timing_carrier.h"\n'
    )
    source = _replace_once(source, header, derived_header, "header")
    variables = "    size_t n = 0;\n    size_t reps = 0;\n"
    source = _replace_once(
        source, variables,
        variables + "    (void)&naux_s4_emit;\n",
        "untimed-parent-reference",
    )
    dataset = (
        "    if (!naux_s4_dataset(argc, argv, &n, &reps)) {\n"
        "        return NAUX_S4_EXIT_USAGE;\n"
        "    }\n\n"
    )
    clock_start = (
        dataset
        + "    struct naux_s4_timestamp start = {0, 0};\n"
        + "    if (!naux_s4_clock_read(&start)) {\n"
        + '        fputs("error\\tclock-start-failed\\n", stderr);\n'
        + "        return NAUX_S4_EXIT_RUNTIME;\n"
        + "    }\n\n"
    )
    source = _replace_once(source, dataset, clock_start, "start-clock")
    tail = (
        "    naux_s4_sink = total;\n"
        "    free(values);\n"
        "    return naux_s4_emit(n, reps, total) ? 0 : NAUX_S4_EXIT_RUNTIME;\n"
        "}\n"
    )
    timing_tail = (
        "    naux_s4_sink = total;\n"
        "    int64_t checksum = 0;\n"
        "    if (!naux_s4_exact_checksum(total, &checksum) || checksum != NAUX_S4_ORACLE) {\n"
        "        free(values);\n"
        '        fputs("error\\tchecksum-mismatch\\n", stderr);\n'
        "        return NAUX_S4_EXIT_RUNTIME;\n"
        "    }\n"
        "    free(values);\n\n"
        "    struct naux_s4_timestamp end = {0, 0};\n"
        "    if (!naux_s4_clock_read(&end)) {\n"
        '        fputs("error\\tclock-end-failed\\n", stderr);\n'
        "        return NAUX_S4_EXIT_RUNTIME;\n"
        "    }\n"
        "    uint64_t duration = 0;\n"
        "    if (!naux_s4_duration_ns(&start, &end, &duration) ||\n"
        "        !naux_s4_write_timing_record(n, reps, checksum, duration)) {\n"
        "        return NAUX_S4_EXIT_RUNTIME;\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
    )
    return _replace_once(source, tail, timing_tail, "checksum-teardown-stop-output").encode()


def _verify_derivations(root: Path, contract: Contract) -> None:
    for record in contract.kernels:
        parent, _lines = _canonical(root / record.parent_path, record.parent_path)
        derived, _derived_lines = _canonical(root / record.derived_path, record.derived_path)
        if _sha256(parent) != record.parent_hash:
            raise CCarrierError(f"WP2 parent hash drifted for {record.name}")
        if _sha256(derived) != record.derived_hash:
            raise CCarrierError(f"derived source hash drifted for {record.name}")
        if derive_source(parent, record) != derived:
            raise CCarrierError(f"derived source is not the exact transformation for {record.name}")

    header, _lines = _canonical(root / "benchmarks/s4/c/timing_carrier.h", "timing carrier header")
    text = header.decode()
    required = (
        'volatile("syscall"',
        "NAUX_S4_SYS_CLOCK_GETTIME = 228",
        "NAUX_S4_CLOCK_MONOTONIC_RAW = 4",
        "naux_s4_exact_checksum",
        "naux_s4_duration_ns",
        "naux_s4_write_timing_record",
        "write(STDOUT_FILENO",
        "NAUX_S4_TIMING_RECORD_BYTES = 56",
    )
    if any(token not in text for token in required) or "clock_gettime(" in text:
        raise CCarrierError("timing carrier header boundary drifted")


def _report(contract: Contract, authority: Authority, mode: str, extras: list[str]) -> tuple[bytes, str]:
    lines = [
        REPORT_MAGIC,
        "status\tc-timing-carriers-structurally-admitted",
        "execution-status\tforbidden",
        "claim-status\tnot-admitted",
        f"mode\t{mode}",
        f"contract-seal\t{contract.seal}",
        f"authority-seal\t{authority.seal}",
        f"wp2-authority-seal\t{WP2_AUTHORITY_SEAL}",
        f"wp7a-authority-seal\t{WP7A_AUTHORITY_SEAL}",
        f"wp7b-naux-authority-seal\t{WP7B_NAUX_AUTHORITY_SEAL}",
        f"roles\t{len(EXPECTED_ROLES)}",
        f"kernels\t{len(contract.kernels)}",
    ]
    lines.extend(extras)
    body = b"".join(f"{line}\n".encode() for line in lines)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve()
    parent = wp2.validate(root)
    if parent.authority.seal != WP2_AUTHORITY_SEAL:
        raise CCarrierError("accepted WP2 parent authority drifted")
    evidence = wp7a.validate(root)
    if evidence.authority.seal != WP7A_AUTHORITY_SEAL:
        raise CCarrierError("accepted WP7A evidence authority drifted")
    naux = wp7b_naux.validate(root)
    if naux.authority.seal != WP7B_NAUX_AUTHORITY_SEAL:
        raise CCarrierError("accepted WP7B NAUX carrier authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/C-TIMING-CARRIER.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/C-TIMING-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_derivations(root, contract)
    extras = [
        f"kernel\t{record.ordinal:02}\t{record.name}\t{record.parent_hash}\t{record.derived_hash}"
        for record in contract.kernels
    ]
    report, report_root = _report(contract, authority, "static-no-execution", extras)
    return Admission(contract, authority, report, report_root)


def _compiler_path(command: str) -> Path:
    located = shutil.which(command)
    if located is None:
        raise CCarrierError("C compiler was not found")
    path = Path(located).resolve()
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise CCarrierError("C compiler is not a regular executable")
    return path


def _compile(argv: list[str], root: Path) -> bytes:
    environment = os.environ.copy()
    environment.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    try:
        completed = subprocess.run(
            argv, cwd=root, input=b"", capture_output=True, check=False,
            timeout=60, env=environment
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CCarrierError("non-executing carrier compilation failed") from error
    if completed.returncode != 0 or completed.stdout != b"" or completed.stderr != b"":
        raise CCarrierError("carrier compilation failed or emitted diagnostics")
    return completed.stdout


def _audit_assembly(raw: bytes, label: str) -> None:
    try:
        assembly = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CCarrierError(f"assembly is not UTF-8 for {label}") from error
    syscalls = list(re.finditer(r"(?m)^\s*syscall\s*$", assembly))
    if len(syscalls) != 2 or "clock_gettime" in assembly:
        raise CCarrierError(f"direct clock syscall count drifted for {label}")
    first = syscalls[0].start()
    second = syscalls[1].start()
    malloc = re.search(r"(?m)^\s*callq?\s+malloc(?:@PLT)?\s*$", assembly[first:second])
    free = re.search(r"(?m)^\s*callq?\s+free(?:@PLT)?\s*$", assembly[first:second])
    write = re.search(r"(?m)^\s*callq?\s+write(?:@PLT)?\s*$", assembly[second:])
    if malloc is None or free is None or malloc.start() >= free.start() or write is None:
        raise CCarrierError(f"allocation/teardown/output order drifted for {label}")
    for syscall in syscalls:
        prefix = assembly[max(0, syscall.start() - 240):syscall.start()]
        if re.search(r"(?:\$|#)228\b", prefix) is None:
            raise CCarrierError(f"clock syscall number is not explicit for {label}")


def compile_audit(root: Path, admission: Admission, cc: str) -> tuple[bytes, str]:
    root = root.resolve()
    compiler = _compiler_path(cc)
    extras = [
        f"compiler\t{_sha256(compiler.read_bytes())}",
        "compiler-output-executed\tno",
    ]
    with tempfile.TemporaryDirectory(prefix="naux-s4-c-carrier-") as directory_name:
        directory = Path(directory_name)
        for role, role_flags in (
            ("c-generic", ()),
            ("c-specialized", SPECIALIZED_FLAGS),
        ):
            for record in admission.contract.kernels:
                source = record.derived_path
                stem = f"{record.ordinal:02}-{role}"
                assembly = directory / f"{stem}.s"
                binary = directory / stem
                base = [str(compiler), *COMMON_FLAGS, *role_flags, source]
                _compile([*base, "-S", "-o", str(assembly)], root)
                _compile([*base, "-o", str(binary)], root)
                assembly_raw = assembly.read_bytes()
                binary_raw = binary.read_bytes()
                _audit_assembly(assembly_raw, stem)
                if (
                    len(binary_raw) < 20
                    or binary_raw[:6] != b"\x7fELF\x02\x01"
                    or binary_raw[18:20] != b"\x3e\x00"
                ):
                    raise CCarrierError(f"compiled carrier is not x86-64 ELF for {stem}")
                extras.append(
                    f"build\t{record.ordinal:02}\t{record.name}\t{role}\t"
                    f"{_sha256(assembly_raw)}\t{_sha256(binary_raw)}"
                )
    return _report(admission.contract, admission.authority, "compile-audit-no-execution", extras)


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
            report, _root = compile_audit(args.root, admission, args.cc)
        if args.report is None:
            sys.stdout.buffer.write(report)
        else:
            args.report.write_bytes(report)
    except (
        CCarrierError,
        wp2.ReferenceError,
        wp7a.EvidenceError,
        wp7b_naux.TimingReplayError,
        OSError,
    ) as error:
        print(f"S4 C timing carriers rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
