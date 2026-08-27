#!/usr/bin/env python3
"""Independently verify the non-executing S4-WP7B timing carrier."""

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

import s4_measurement_evidence as wp7a
import s4_residual_process as wp5e


CONTRACT_MAGIC = "NAUX-S4-RESIDUAL-TIMING-CARRIER-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-RESIDUAL-TIMING-CARRIER-AUTHORITY\t1"
CANDIDATE_MAGIC = "NAUX-S4-RESIDUAL-TIMING-CARRIER\t1"
REPORT_MAGIC = "NAUX-S4-RESIDUAL-TIMING-CARRIER-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-residual-timing-carrier:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-residual-timing-carrier:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-residual-timing-carrier:report:v1\0"
WP5E_AUTHORITY_SEAL = "098a7cb2216359c03ab1e58d3a41f6c904d411ccafa1c10b0a88885fc3dfc53f"
WP5F_AUTHORITY_SEAL = "1d85ad923f5db2eb520cee9d3582bbc97f63b711c67d5d4b44d5859fb0fa92bd"
WP7A_AUTHORITY_SEAL = "7e10bc03b30b532f05e67c6f6d3ce80d7430125bcae7b9e3824c86cfc233f0bc"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")

ELF_BASE = 0x0040_0000
ELF_ENTRY_OFFSET = 0x100
ELF_ENTRY = ELF_BASE + ELF_ENTRY_OFFSET
ELF_HEADER_BYTES = 64
PROGRAM_HEADER_BYTES = 56
PROGRAM_HEADER_COUNT = 2
TARGET_ALIGNMENT = 16
STACK_BYTES = 96
START_SECONDS = 0
START_NANOSECONDS = 8
END_SECONDS = 16
END_NANOSECONDS = 24
RESULT_OFFSET = 32
CHECKSUM_OFFSET = 48
OUTER_OFFSET = 56
INNER_OFFSET = 64
OWNER_OFFSET = 72
DURATION_OFFSET = 80
CLOCK_MONOTONIC_RAW = 4
SYS_WRITE = 1
SYS_CLOCK_GETTIME = 228
SYS_EXIT = 60
FAILURE_EXIT_CODE = 71
NANOSECONDS_PER_SECOND = 1_000_000_000
RESULT_MAGIC = b"NAUX7B01"
RESULT_BYTES = 56
MAX_TARGET_BYTES = 1_048_576
MAX_ELF_BYTES = 1_114_112

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-process-authority", WP5E_AUTHORITY_SEAL),
    ("parent-role-authority", WP5F_AUTHORITY_SEAL),
    ("parent-evidence-law-authority", WP7A_AUTHORITY_SEAL),
    ("status", "naux-timing-carrier-structurally-admitted"),
    ("execution-status", "forbidden"),
    ("claim-status", "not-admitted"),
    ("clock-source", "clock-monotonic-raw"),
    ("clock-reads", "2"),
    ("clock-placement", "before-exact-target-after-target-and-checksum-validation"),
    ("target-preservation", "byte-exact-wp5e-process-target"),
    ("oracle-policy", "startup-validation-only-never-target-output-substitution"),
    ("result-protocol", "fixed-le56-v1"),
    ("allowed-syscalls", "mmap-munmap-clock-gettime-write-exit"),
    ("linker", "none"),
    ("libc", "none"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("kernel-count", "4"),
)
CONTRACT_CLOSURES = (
    ("01", "naux-in-role-timing-carrier-unavailable", "closed", "wp7b-exact-wrapper"),
)
CONTRACT_BLOCKERS = (
    ("01", "c-generic-in-role-timing-carrier-unavailable"),
    ("02", "c-specialized-in-role-timing-carrier-unavailable"),
    ("03", "retained-controlled-host-attestation-unavailable"),
    ("04", "measurement-runner-unavailable"),
    ("05", "raw-measurement-evidence-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP7B"),
    ("authority-id", "s4-naux-residual-timing-carrier-v1"),
    ("status", "naux-timing-carrier-structurally-admitted"),
    ("execution-status", "forbidden"),
    ("claim-status", "not-admitted"),
    ("file-count", "8"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-residual-timing.yml",
    "distribution/s4-performance/WP7B-CARRIER.tsv",
    "distribution/s4-performance/WP7B-NONCLAIMS.md",
    "distribution/s4-performance/WP7B-README.md",
    "naux-lang/examples/naux_s4_residual_timing.rs",
    "naux-lang/examples/support/s4_residual_timing_elf.rs",
    "scripts/s4_residual_timing.py",
    "scripts/tests/test_s4_residual_timing.py",
)
CANDIDATE_METADATA = (
    ("status", "structural-timing-carrier-candidate"),
    ("execution-status", "forbidden"),
    ("clock-source", "clock-monotonic-raw"),
    ("clock-placement", "before-target-after-checksum-validation"),
    ("result-protocol", "fixed-le56-v1"),
    ("allowed-syscalls", "mmap-munmap-clock-gettime-write-exit"),
    ("target", "x86_64-unknown-linux-gnu"),
)
CANDIDATE_COLUMNS = (
    "columns\tordinal\tkernel\twork-hash\toracle\tprocess-target-bytes\t"
    "timing-elf-bytes\tstartup-bytes\ttarget-offset"
)


class TimingReplayError(RuntimeError):
    """A fail-closed S4-WP7B carrier-replay error."""


@dataclass(frozen=True)
class ContractRecord:
    ordinal: int
    name: str
    oracle: int
    work_hash: str
    target_bytes: int
    target_hash: str
    elf_bytes: int
    startup_bytes: int
    target_offset: int
    elf_hash: str


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
    files: tuple[FileRecord, ...]
    seal: str


@dataclass(frozen=True)
class Admission:
    contract: Contract
    authority: Authority
    static_report: bytes
    static_root: str


@dataclass(frozen=True)
class Kernel:
    record: ContractRecord
    target: bytes
    elf: bytes


@dataclass(frozen=True)
class Candidate:
    kernels: tuple[Kernel, ...]
    raw: bytes


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(raw: bytes, label: str, maximum: int = 2_000_000) -> list[str]:
    if not raw or len(raw) > maximum or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise TimingReplayError(f"{label} has invalid extent or encoding")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TimingReplayError(f"{label} is not UTF-8") from error
    lines = text.splitlines()
    if any(not line for line in lines):
        raise TimingReplayError(f"{label} contains a blank row")
    return lines


def _sealed_lines(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise TimingReplayError(f"{path.name} is not a regular file")
    lines = _canonical(path.read_bytes(), path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise TimingReplayError(f"{path.name} shape or magic drifted")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise TimingReplayError(f"{path.name} seal row is malformed")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if _sha256(domain + body) != fields[1]:
        raise TimingReplayError(f"{path.name} seal verification failed")
    return lines, fields[1]


def _uint(value: str, label: str) -> int:
    if not UINT_RE.fullmatch(value):
        raise TimingReplayError(f"{label} is not a canonical unsigned integer")
    return int(value)


def _int(value: str, label: str) -> int:
    if not INT_RE.fullmatch(value):
        raise TimingReplayError(f"{label} is not a canonical integer")
    return int(value)


def parse_contract(path: Path) -> Contract:
    lines, seal = _sealed_lines(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    index = 1
    metadata: list[tuple[str, str]] = []
    while index < len(lines) - 1 and lines[index].startswith("meta\t"):
        fields = lines[index].split("\t")
        if len(fields) != 3:
            raise TimingReplayError("WP7B contract metadata is malformed")
        metadata.append((fields[1], fields[2]))
        index += 1
    if tuple(metadata) != CONTRACT_METADATA:
        raise TimingReplayError("WP7B contract metadata drifted")
    records: list[ContractRecord] = []
    while index < len(lines) - 1 and lines[index].startswith("kernel\t"):
        fields = lines[index].split("\t")
        if (
            len(fields) != 11
            or fields[1] != f"{len(records) + 1:02}"
            or not HASH_RE.fullmatch(fields[4])
            or not HASH_RE.fullmatch(fields[6])
            or not HASH_RE.fullmatch(fields[10])
        ):
            raise TimingReplayError("WP7B kernel record is malformed")
        record = ContractRecord(
            int(fields[1]),
            fields[2],
            _int(fields[3], "kernel oracle"),
            fields[4],
            _uint(fields[5], "target bytes"),
            fields[6],
            _uint(fields[7], "ELF bytes"),
            _uint(fields[8], "startup bytes"),
            _uint(fields[9], "target offset"),
            fields[10],
        )
        if (
            record.target_bytes == 0
            or record.target_bytes > MAX_TARGET_BYTES
            or record.elf_bytes == 0
            or record.elf_bytes > MAX_ELF_BYTES
            or record.startup_bytes == 0
            or record.target_offset < ELF_ENTRY_OFFSET + record.startup_bytes
            or record.target_offset % TARGET_ALIGNMENT != 0
            or record.target_offset + record.target_bytes != record.elf_bytes
        ):
            raise TimingReplayError("WP7B kernel extent or alignment drifted")
        records.append(record)
        index += 1
    closures: list[tuple[str, str, str, str]] = []
    while index < len(lines) - 1 and lines[index].startswith("closure\t"):
        fields = lines[index].split("\t")
        if len(fields) != 5:
            raise TimingReplayError("WP7B closure row is malformed")
        closures.append(tuple(fields[1:]))
        index += 1
    blockers: list[tuple[str, str]] = []
    while index < len(lines) - 1 and lines[index].startswith("blocker\t"):
        fields = lines[index].split("\t")
        if len(fields) != 3:
            raise TimingReplayError("WP7B blocker row is malformed")
        blockers.append((fields[1], fields[2]))
        index += 1
    expected = tuple((ordinal, name, oracle) for ordinal, name, oracle in wp7a.KERNELS)
    actual = tuple((f"{record.ordinal:02}", record.name, record.oracle) for record in records)
    if actual != expected or tuple(closures) != CONTRACT_CLOSURES:
        raise TimingReplayError("WP7B kernel identity or closure set drifted")
    if tuple(blockers) != CONTRACT_BLOCKERS or index != len(lines) - 1:
        raise TimingReplayError("WP7B blocker set or extent drifted")
    return Contract(tuple(records), seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed_lines(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    index = 1
    metadata: list[tuple[str, str]] = []
    while index < len(lines) - 1 and lines[index].startswith("meta\t"):
        fields = lines[index].split("\t")
        if len(fields) != 3:
            raise TimingReplayError("WP7B authority metadata is malformed")
        metadata.append((fields[1], fields[2]))
        index += 1
    if tuple(metadata) != AUTHORITY_METADATA:
        raise TimingReplayError("WP7B authority metadata drifted")
    expected_links = (
        f"component\ttiming-carrier\tdistribution/s4-performance/WP7B-CARRIER.tsv\t{contract_seal}",
        f"parent\tprocess-authority\tdistribution/s4-performance/WP5E-AUTHORITY.tsv\t{WP5E_AUTHORITY_SEAL}",
        f"parent\trole-authority\tdistribution/s4-performance/WP5F-AUTHORITY.tsv\t{WP5F_AUTHORITY_SEAL}",
        f"parent\tevidence-law-authority\tdistribution/s4-performance/WP7A-AUTHORITY.tsv\t{WP7A_AUTHORITY_SEAL}",
    )
    if tuple(lines[index : index + 4]) != expected_links:
        raise TimingReplayError("WP7B component or parent binding drifted")
    index += 4
    files: list[FileRecord] = []
    while index < len(lines) - 1:
        fields = lines[index].split("\t")
        if (
            len(fields) != 6
            or fields[0] != "file"
            or not MODE_RE.fullmatch(fields[1])
            or not UINT_RE.fullmatch(fields[2])
            or not HASH_RE.fullmatch(fields[3])
            or not PATH_RE.fullmatch(fields[4])
            or fields[5] != "timing-carrier"
        ):
            raise TimingReplayError("WP7B authority file row is malformed")
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
        index += 1
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise TimingReplayError("WP7B authority file inventory drifted")
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise TimingReplayError(f"WP7B bound file is not regular: {record.path}")
        raw = path.read_bytes()
        mode = stat.S_IFREG | stat.S_IMODE(metadata.st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise TimingReplayError(f"WP7B bound file drifted: {record.path}")


def _verify_source_boundary(root: Path) -> None:
    workflow = (root / ".github/workflows/s4-residual-timing.yml").read_text()
    for token in ("cargo test", "cargo build", "scripts/s4_residual_timing.py", "test_s4_residual_timing"):
        if token not in workflow:
            raise TimingReplayError("WP7B workflow omits a structural gate")
    support = (root / "naux-lang/examples/support/s4_residual_timing_elf.rs").read_text()
    for _ordinal, name, oracle in wp7a.KERNELS:
        if name in support or str(oracle) in support or f"{oracle:_}" in support:
            raise TimingReplayError("generic WP7B support contains kernel dispatch or oracle literals")
    script = (root / "scripts/s4_residual_timing.py").read_text()
    forbidden_tokens = (
        "_run_" + "process_image",
        "material" + "ize",
        "chmod" + "(0o700)",
        "perf_" + "counter",
        "clock_" + "gettime(",
    )
    for forbidden in forbidden_tokens:
        if forbidden in script:
            raise TimingReplayError("WP7B verifier contains generated-image execution or timing support")
    expected = {"WP7B-AUTHORITY.tsv", "WP7B-CARRIER.tsv", "WP7B-NONCLAIMS.md", "WP7B-README.md"}
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP7B-*")
        if path.is_file()
    }
    if actual != expected:
        raise TimingReplayError("unexpected WP7B distribution artifact")


def _report(contract: Contract, authority: Authority, candidate: Candidate | None) -> bytes:
    rows = [
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"parent-evidence-law\t{WP7A_AUTHORITY_SEAL}",
        "status\tnaux-timing-carrier-structurally-admitted",
        "execution-status\tforbidden",
        "claim-status\tnot-admitted",
        "clock-source\tclock-monotonic-raw",
        "clock-reads\t2",
        "kernels\t4",
    ]
    if candidate is None:
        rows.append("mode\tstatic-authority")
    else:
        rows.extend(
            (
                "mode\tindependent-byte-replay-no-execution",
                f"candidate\t{_sha256(candidate.raw)}",
                f"target-aggregate\t{_sha256(''.join(kernel.record.target_hash for kernel in candidate.kernels).encode())}",
                f"elf-aggregate\t{_sha256(''.join(kernel.record.elf_hash for kernel in candidate.kernels).encode())}",
            )
        )
    body = b"".join(f"{row}\n".encode() for row in rows)
    return body + f"report-root\t{_sha256(REPORT_DOMAIN + body)}\n".encode()


def validate(root: Path) -> Admission:
    root = root.resolve()
    law = wp7a.validate(root)
    if law.authority.seal != WP7A_AUTHORITY_SEAL:
        raise TimingReplayError("WP7A parent authority drifted")
    process = wp5e.validate(root)
    if process.authority.seal != WP5E_AUTHORITY_SEAL:
        raise TimingReplayError("WP5E parent authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP7B-CARRIER.tsv")
    if tuple(record.target_hash for record in contract.records) != tuple(
        record.process_target_hash for record in process.contract.records
    ):
        raise TimingReplayError("WP7B targets differ from exact WP5E process targets")
    if tuple(record.work_hash for record in contract.records) != tuple(
        record.work_hash for record in process.contract.records
    ):
        raise TimingReplayError("WP7B work identities differ from WP5E")
    authority = parse_authority(
        root / "distribution/s4-performance/WP7B-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_source_boundary(root)
    report = _report(contract, authority, None)
    static_root = report.decode().split("report-root\t", 1)[1].strip()
    return Admission(contract, authority, report, static_root)


def _emit_jcc(result: bytearray, opcode: bytes) -> int:
    result.extend(opcode)
    displacement = len(result)
    result.extend(b"\0" * 4)
    return displacement


def _patch_rel32(result: bytearray, displacement: int, target: int) -> None:
    next_offset = displacement + 4
    delta = target - next_offset
    if not -(1 << 31) <= delta < (1 << 31) or next_offset > len(result):
        raise TimingReplayError("timing startup rel32 is out of range")
    result[displacement:next_offset] = struct.pack("<i", delta)


def _lea_rsi_rsp(result: bytearray, offset: int) -> None:
    result.extend(b"\x48\x8d\x74\x24" + bytes((offset,)))


def _load_rax_rsp(result: bytearray, offset: int) -> None:
    result.extend(b"\x48\x8b\x44\x24" + bytes((offset,)))


def _load_r8_rsp(result: bytearray, offset: int) -> None:
    result.extend(b"\x4c\x8b\x44\x24" + bytes((offset,)))


def _store(result: bytearray, prefix: bytes, offset: int) -> None:
    result.extend(prefix + bytes((offset,)))


def _mov_r8(result: bytearray, value: int) -> None:
    result.extend(b"\x49\xb8" + struct.pack("<Q", value & ((1 << 64) - 1)))


def _clock_read(result: bytearray, offset: int, failures: list[int]) -> None:
    result.extend(b"\xb8" + struct.pack("<I", SYS_CLOCK_GETTIME))
    result.extend(b"\xbf" + struct.pack("<I", CLOCK_MONOTONIC_RAW))
    _lea_rsi_rsp(result, offset)
    result.extend(b"\x0f\x05\x48\x85\xc0")
    failures.append(_emit_jcc(result, b"\x0f\x85"))


def _validate_nanoseconds(result: bytearray, offset: int, failures: list[int]) -> None:
    _load_r8_rsp(result, offset)
    result.extend(b"\x4d\x85\xc0")
    failures.append(_emit_jcc(result, b"\x0f\x88"))
    result.extend(b"\x49\xc7\xc2" + struct.pack("<I", NANOSECONDS_PER_SECOND))
    result.extend(b"\x4d\x39\xd0")
    failures.append(_emit_jcc(result, b"\x0f\x83"))


def _startup(ordinal: int, oracle: int, target_offset: int) -> bytes:
    result = bytearray(b"\x48\x83\xec" + bytes((STACK_BYTES,)))
    failures: list[int] = []
    _clock_read(result, START_SECONDS, failures)
    call = len(result)
    result.extend(b"\xe8\0\0\0\0")
    call_delta = target_offset - (ELF_ENTRY_OFFSET + call + 5)
    if not -(1 << 31) <= call_delta < (1 << 31):
        raise TimingReplayError("timing target exceeds call rel32")
    result[call + 1 : call + 5] = struct.pack("<i", call_delta)
    _store(result, b"\x48\x89\x44\x24", CHECKSUM_OFFSET)
    _store(result, b"\x48\x89\x4c\x24", OUTER_OFFSET)
    _store(result, b"\x48\x89\x54\x24", INNER_OFFSET)
    _store(result, b"\x48\x89\x74\x24", OWNER_OFFSET)
    _mov_r8(result, oracle)
    result.extend(b"\x4c\x39\xc0")
    failures.append(_emit_jcc(result, b"\x0f\x85"))
    _clock_read(result, END_SECONDS, failures)
    _validate_nanoseconds(result, START_NANOSECONDS, failures)
    _validate_nanoseconds(result, END_NANOSECONDS, failures)
    _load_rax_rsp(result, END_SECONDS)
    result.extend(b"\x48\x2b\x04\x24")
    failures.append(_emit_jcc(result, b"\x0f\x88"))
    result.extend(b"\x48\x69\xc0" + struct.pack("<I", NANOSECONDS_PER_SECOND))
    failures.append(_emit_jcc(result, b"\x0f\x80"))
    _load_r8_rsp(result, END_NANOSECONDS)
    result.extend(b"\x4c\x01\xc0")
    failures.append(_emit_jcc(result, b"\x0f\x80"))
    _load_r8_rsp(result, START_NANOSECONDS)
    result.extend(b"\x4c\x29\xc0")
    failures.append(_emit_jcc(result, b"\x0f\x88"))
    result.extend(b"\x48\x85\xc0")
    failures.append(_emit_jcc(result, b"\x0f\x8e"))
    _store(result, b"\x48\x89\x44\x24", DURATION_OFFSET)
    _mov_r8(result, int.from_bytes(RESULT_MAGIC, "little"))
    _store(result, b"\x4c\x89\x44\x24", RESULT_OFFSET)
    _mov_r8(result, ordinal)
    _store(result, b"\x4c\x89\x44\x24", RESULT_OFFSET + 8)
    result.extend(b"\xb8" + struct.pack("<I", SYS_WRITE))
    result.extend(b"\xbf" + struct.pack("<I", 1))
    _lea_rsi_rsp(result, RESULT_OFFSET)
    result.extend(b"\xba" + struct.pack("<I", RESULT_BYTES))
    result.extend(b"\x0f\x05\x48\x83\xf8" + bytes((RESULT_BYTES,)))
    failures.append(_emit_jcc(result, b"\x0f\x85"))
    result.extend(b"\x48\x83\xc4" + bytes((STACK_BYTES,)))
    result.extend(b"\x31\xff\xb8" + struct.pack("<I", SYS_EXIT) + b"\x0f\x05\x0f\x0b")
    failure = len(result)
    result.extend(
        b"\xbf"
        + struct.pack("<I", FAILURE_EXIT_CODE)
        + b"\xb8"
        + struct.pack("<I", SYS_EXIT)
        + b"\x0f\x05\x0f\x0b"
    )
    for displacement in failures:
        _patch_rel32(result, displacement, failure)
    return bytes(result)


def _elf_header(image_bytes: int) -> bytes:
    identity = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\0" * 8
    header = identity + struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        62,
        1,
        ELF_ENTRY,
        ELF_HEADER_BYTES,
        0,
        0,
        ELF_HEADER_BYTES,
        PROGRAM_HEADER_BYTES,
        PROGRAM_HEADER_COUNT,
        0,
        0,
        0,
    )
    load = struct.pack(
        "<IIQQQQQQ", 1, 5, 0, ELF_BASE, ELF_BASE, image_bytes, image_bytes, 4096
    )
    stack = struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
    return header + load + stack


def _reconstruct_elf(record: ContractRecord, target: bytes) -> bytes:
    provisional = _startup(record.ordinal, record.oracle, 0)
    target_offset = (
        ELF_ENTRY_OFFSET + len(provisional) + TARGET_ALIGNMENT - 1
    ) & -TARGET_ALIGNMENT
    startup = _startup(record.ordinal, record.oracle, target_offset)
    image_bytes = target_offset + len(target)
    result = bytearray(_elf_header(image_bytes))
    result.extend(b"\0" * (ELF_ENTRY_OFFSET - len(result)))
    result.extend(startup)
    result.extend(b"\0" * (target_offset - len(result)))
    result.extend(target)
    if (
        len(startup) != record.startup_bytes
        or target_offset != record.target_offset
        or len(result) != record.elf_bytes
    ):
        raise TimingReplayError(f"{record.name} timing layout receipt drifted")
    return bytes(result)


def _verify_order(record: ContractRecord, elf: bytes) -> None:
    startup = elf[ELF_ENTRY_OFFSET : record.target_offset]
    first_clock = b"\xb8" + struct.pack("<I", SYS_CLOCK_GETTIME) + b"\xbf" + struct.pack("<I", CLOCK_MONOTONIC_RAW) + b"\x48\x8d\x74\x24\x00"
    second_clock = b"\xb8" + struct.pack("<I", SYS_CLOCK_GETTIME) + b"\xbf" + struct.pack("<I", CLOCK_MONOTONIC_RAW) + b"\x48\x8d\x74\x24\x10"
    oracle_compare = b"\x49\xb8" + struct.pack("<Q", record.oracle & ((1 << 64) - 1)) + b"\x4c\x39\xc0"
    write = b"\xb8" + struct.pack("<I", SYS_WRITE) + b"\xbf" + struct.pack("<I", 1)
    call_positions = []
    for position, byte in enumerate(startup):
        if byte != 0xE8 or position + 5 > len(startup):
            continue
        delta = struct.unpack_from("<i", startup, position + 1)[0]
        if ELF_ENTRY_OFFSET + position + 5 + delta == record.target_offset:
            call_positions.append(position)
    positions = (
        startup.find(first_clock),
        call_positions[0] if len(call_positions) == 1 else -1,
        startup.find(oracle_compare),
        startup.find(second_clock),
        startup.find(RESULT_MAGIC),
        startup.find(write),
    )
    if any(position < 0 for position in positions) or tuple(sorted(positions)) != positions:
        raise TimingReplayError(f"{record.name} clock, target, validation, or output order drifted")
    if startup.count(first_clock) != 1 or startup.count(second_clock) != 1:
        raise TimingReplayError(f"{record.name} clock read multiplicity drifted")


def _verify_kernel(kernel: Kernel) -> None:
    record = kernel.record
    if (
        len(kernel.target) != record.target_bytes
        or _sha256(kernel.target) != record.target_hash
        or len(kernel.elf) != record.elf_bytes
        or _sha256(kernel.elf) != record.elf_hash
        or kernel.elf[:4] != b"\x7fELF"
        or kernel.elf[record.target_offset :] != kernel.target
    ):
        raise TimingReplayError(f"{record.name} target or ELF identity drifted")
    if kernel.elf != _reconstruct_elf(record, kernel.target):
        raise TimingReplayError(f"{record.name} independent ELF reconstruction differs")
    _verify_order(record, kernel.elf)


def parse_candidate(raw: bytes, contract: Contract) -> Candidate:
    lines = _canonical(raw, "WP7B emitter output")
    if lines[0] != CANDIDATE_MAGIC:
        raise TimingReplayError("WP7B candidate magic drifted")
    index = 1
    metadata: list[tuple[str, str]] = []
    while index < len(lines) and lines[index].startswith("meta\t"):
        fields = lines[index].split("\t")
        if len(fields) != 3:
            raise TimingReplayError("WP7B candidate metadata is malformed")
        metadata.append((fields[1], fields[2]))
        index += 1
    if tuple(metadata) != CANDIDATE_METADATA or index >= len(lines) or lines[index] != CANDIDATE_COLUMNS:
        raise TimingReplayError("WP7B candidate metadata or columns drifted")
    index += 1
    kernels: list[Kernel] = []
    for record in contract.records:
        if index + 2 >= len(lines):
            raise TimingReplayError("WP7B candidate is truncated")
        fields = lines[index].split("\t")
        expected = (
            "kernel",
            f"{record.ordinal:02}",
            record.name,
            record.work_hash,
            str(record.oracle),
            str(record.target_bytes),
            str(record.elf_bytes),
            str(record.startup_bytes),
            str(record.target_offset),
        )
        if tuple(fields) != expected:
            raise TimingReplayError(f"{record.name} candidate receipt drifted")
        target_fields = lines[index + 1].split("\t")
        elf_fields = lines[index + 2].split("\t")
        if target_fields[:2] != ["target-hex", f"{record.ordinal:02}"] or elf_fields[:2] != ["elf-hex", f"{record.ordinal:02}"]:
            raise TimingReplayError(f"{record.name} candidate payload identity drifted")
        try:
            target = bytes.fromhex(target_fields[2])
            elf = bytes.fromhex(elf_fields[2])
        except (IndexError, ValueError) as error:
            raise TimingReplayError(f"{record.name} candidate payload is not canonical hex") from error
        if target.hex() != target_fields[2] or elf.hex() != elf_fields[2]:
            raise TimingReplayError(f"{record.name} candidate payload is not lowercase exact hex")
        kernel = Kernel(record, target, elf)
        _verify_kernel(kernel)
        kernels.append(kernel)
        index += 3
    if index != len(lines) - 1 or lines[index] != "verification\tregenerated-no-execution":
        raise TimingReplayError("WP7B candidate has trailing or missing rows")
    return Candidate(tuple(kernels), raw)


def _looks_like_generated_image(binary: Path) -> bool:
    with binary.open("rb") as stream:
        header = stream.read(20)
    return (
        len(header) == 20
        and header[:7] == b"\x7fELF\x02\x01\x01"
        and struct.unpack_from("<HH", header, 16) == (2, 62)
    )


def _validate_emitter_binary(binary: Path) -> None:
    metadata = binary.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or not os.access(binary, os.X_OK):
        raise TimingReplayError("reviewed WP7B emitter is not a regular executable")
    if binary.name != "naux_s4_residual_timing":
        raise TimingReplayError("reviewed WP7B emitter has a noncanonical filename")
    if _looks_like_generated_image(binary):
        raise TimingReplayError("refusing to execute a generated timing image as the WP7B emitter")


def _run_emitter(binary: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [os.fspath(binary)],
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C"},
        check=False,
        timeout=30,
    )


def replay(admission: Admission, binary: Path) -> tuple[bytes, Candidate]:
    _validate_emitter_binary(binary)
    reviewed = binary.resolve(strict=True)
    first = _run_emitter(reviewed)
    second = _run_emitter(reviewed)
    if any(completed.returncode != 0 or completed.stderr for completed in (first, second)):
        raise TimingReplayError("WP7B emitter did not exit cleanly and silently")
    if first.stdout != second.stdout:
        raise TimingReplayError("WP7B emitter is nondeterministic")
    candidate = parse_candidate(first.stdout, admission.contract)
    return _report(admission.contract, admission.authority, candidate), candidate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--binary", type=Path)
    arguments = parser.parse_args()
    try:
        admission = validate(arguments.root.resolve())
        if arguments.binary is None:
            sys.stdout.buffer.write(admission.static_report)
        else:
            report, _candidate = replay(admission, arguments.binary)
            sys.stdout.buffer.write(report)
    except (
        TimingReplayError,
        wp7a.EvidenceError,
        wp5e.ProcessReplayError,
        OSError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"S4-WP7B validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
