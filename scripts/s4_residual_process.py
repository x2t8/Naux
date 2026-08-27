#!/usr/bin/env python3
"""Admit and execute the clock-free S4-WP5E residual process boundary."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import s4_residual_elf64 as wp5d


CONTRACT_MAGIC = "NAUX-S4-RESIDUAL-PROCESS-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-RESIDUAL-PROCESS-AUTHORITY\t1"
CANDIDATE_MAGIC = "NAUX-S4-RESIDUAL-PROCESS\t1"
REPORT_MAGIC = "NAUX-S4-RESIDUAL-PROCESS-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-residual-process:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-residual-process:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-residual-process:report:v1\0"
WP5D_CONTRACT_SEAL = "4219b6842f92d659daa4ed5bc144ae312710010d7f763b0e27bfd4ba3957518c"
WP5D_AUTHORITY_SEAL = "eba915d65c448d0251c4b253c911d61e2f06b8d4bcc4cf3e57a7eea78bd87fb4"
RESULT_MAGIC = b"NAUX5E01"
RESULT_STRUCT = struct.Struct("<8sQqQQQ")
RESULT_BYTES = RESULT_STRUCT.size
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
MAX_CANDIDATE_BYTES = 256_000
MAX_TARGET_BYTES = 1_048_576
MAX_ELF_BYTES = 1_114_112
ELF_BASE = 0x0040_0000
ELF_ENTRY_OFFSET = 0x100
ELF_ENTRY = ELF_BASE + ELF_ENTRY_OFFSET
TARGET_ALIGNMENT = 16
FAILURE_EXIT_CODE = 70
EXPECTED_KERNELS = (
    ("01", "sum-dense", 6_710_476_800),
    ("02", "branch-mix", -69_189_632),
    ("03", "dot-product", 73_294_064_435_200),
    ("04", "list-update", 6_730_547_200),
)
CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-contract", WP5D_CONTRACT_SEAL),
    ("parent-authority", WP5D_AUTHORITY_SEAL),
    ("status", "fresh-process-checksum-work-parity-admitted"),
    ("claim-status", "untimed-parity-only"),
    ("timing-status", "forbidden"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("dataset", "static-n16384-r50"),
    ("result-protocol", "fixed-le48-v1"),
    ("work-proof", "sealed-structure-plus-terminal-frame-state"),
    ("pipeline", "single-wp5d-target-to-process-wrapper"),
    ("kernel-count", "4"),
    ("replay-count", "2"),
    ("linker", "none"),
    ("libc", "none"),
    ("allowed-syscalls", "mmap-munmap-write-exit"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP5E"),
    ("authority-id", "s4-residual-process-v1"),
    ("status", "fresh-process-checksum-work-parity-admitted"),
    ("claim-status", "untimed-parity-only"),
    ("timing-status", "forbidden"),
    ("kernel-count", "4"),
    ("file-count", "8"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-residual-process.yml",
    "distribution/s4-performance/WP5E-NONCLAIMS.md",
    "distribution/s4-performance/WP5E-README.md",
    "distribution/s4-performance/WP5E-PROCESS.tsv",
    "naux-lang/examples/naux_s4_residual_process.rs",
    "naux-lang/examples/support/s4_residual_process_elf.rs",
    "scripts/s4_residual_process.py",
    "scripts/tests/test_s4_residual_process.py",
)
COLUMNS = (
    "columns\tordinal\tkernel\twork-hash\tparent-target-bytes\tprocess-target-bytes\t"
    "error-offset\treturn-start\tverifier-offset\tchecksum-displacement\t"
    "outer-displacement\tinner-displacement\towner-displacement\texpected-outer\t"
    "expected-inner\telf-bytes\tstartup-bytes\ttarget-offset"
)
META_ROWS = (
    "meta\tstatus\tfresh-process-artifact-candidate",
    "meta\texecution-owner\twp5e-only",
    "meta\ttiming-status\tforbidden",
    "meta\tresult-protocol\tfixed-le48-v1",
    "meta\tallowed-syscalls\tmmap-munmap-write-exit",
    "meta\tlinker\tnone",
    "meta\tlibc\tnone",
    "meta\ttarget\tx86_64-unknown-linux-gnu",
)
FORBIDDEN_EMITTER_SOURCE = (
    "instant::",
    "systemtime::",
    ".elapsed()",
    "duration_since(",
    "runtime_ns",
    "compile_ns",
    "command::new",
    "std::process::command",
    "gcc",
    "clang",
    "objcopy",
    "throughput",
    "latency",
    "median",
)


class ProcessReplayError(RuntimeError):
    """A fail-closed S4-WP5E admission or execution error."""


@dataclass(frozen=True)
class ContractRecord:
    ordinal: int
    name: str
    oracle: int
    work_hash: str
    parent_target_hash: str
    process_target_hash: str
    elf_hash: str
    parent_target_bytes: int
    process_target_bytes: int
    error_offset: int
    return_start: int
    verifier_offset: int
    checksum_displacement: int
    outer_displacement: int
    inner_displacement: int
    owner_displacement: int
    expected_outer: int
    expected_inner: int
    elf_bytes: int
    startup_bytes: int
    target_offset: int


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
class Kernel:
    record: ContractRecord
    parent_target: bytes
    process_target: bytes
    elf: bytes


@dataclass(frozen=True)
class Candidate:
    kernels: tuple[Kernel, ...]
    raw: bytes


@dataclass(frozen=True)
class ProcessResult:
    pass_number: int
    ordinal: int
    name: str
    checksum: int
    outer: int
    inner: int
    owner: int


@dataclass(frozen=True)
class Admission:
    contract: Contract
    authority: Authority
    static_report: bytes
    report_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(raw: bytes, label: str, limit: int) -> list[str]:
    if not raw or len(raw) > limit or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise ProcessReplayError(f"{label} has an invalid canonical extent")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProcessReplayError(f"{label} is not UTF-8") from error
    lines = text.splitlines()
    if any(not line or line != line.strip() for line in lines):
        raise ProcessReplayError(f"{label} contains blank or padded rows")
    return lines


def _uint(value: str, label: str) -> int:
    if UINT_RE.fullmatch(value) is None:
        raise ProcessReplayError(f"{label} is not canonical unsigned decimal")
    return int(value)


def _int(value: str, label: str) -> int:
    if INT_RE.fullmatch(value) is None:
        raise ProcessReplayError(f"{label} is not canonical signed decimal")
    return int(value)


def _hash(value: str, label: str) -> str:
    if HASH_RE.fullmatch(value) is None:
        raise ProcessReplayError(f"{label} is not lowercase SHA-256")
    return value


def parse_contract(path: Path) -> Contract:
    if path.is_symlink() or not path.is_file():
        raise ProcessReplayError("WP5E contract is not a regular file")
    raw = path.read_bytes()
    lines = _canonical(raw, "WP5E contract", 32_000)
    expected_rows = 1 + len(CONTRACT_METADATA) + len(EXPECTED_KERNELS) + 1
    if len(lines) != expected_rows or lines[0] != CONTRACT_MAGIC:
        raise ProcessReplayError("WP5E contract shape or magic drifted")
    cursor = 1
    for key, value in CONTRACT_METADATA:
        if lines[cursor] != f"meta\t{key}\t{value}":
            raise ProcessReplayError(f"WP5E contract metadata `{key}` drifted")
        cursor += 1
    records: list[ContractRecord] = []
    for expected_ordinal, expected_name, expected_oracle in EXPECTED_KERNELS:
        fields = lines[cursor].split("\t")
        cursor += 1
        if len(fields) != 22 or fields[0] != "kernel":
            raise ProcessReplayError("WP5E kernel contract row is malformed")
        if fields[1] != expected_ordinal or fields[2] != expected_name:
            raise ProcessReplayError("WP5E kernel order or identity drifted")
        oracle = _int(fields[3], f"{expected_name} oracle")
        if oracle != expected_oracle:
            raise ProcessReplayError(f"{expected_name} checksum oracle drifted")
        record = ContractRecord(
            ordinal=int(expected_ordinal),
            name=expected_name,
            oracle=oracle,
            work_hash=_hash(fields[4], "work hash"),
            parent_target_hash=_hash(fields[5], "parent target hash"),
            process_target_hash=_hash(fields[6], "process target hash"),
            elf_hash=_hash(fields[7], "ELF hash"),
            parent_target_bytes=_uint(fields[8], "parent target bytes"),
            process_target_bytes=_uint(fields[9], "process target bytes"),
            error_offset=_uint(fields[10], "error offset"),
            return_start=_uint(fields[11], "return start"),
            verifier_offset=_uint(fields[12], "verifier offset"),
            checksum_displacement=_int(fields[13], "checksum displacement"),
            outer_displacement=_int(fields[14], "outer displacement"),
            inner_displacement=_int(fields[15], "inner displacement"),
            owner_displacement=_int(fields[16], "owner displacement"),
            expected_outer=_uint(fields[17], "expected outer"),
            expected_inner=_uint(fields[18], "expected inner"),
            elf_bytes=_uint(fields[19], "ELF bytes"),
            startup_bytes=_uint(fields[20], "startup bytes"),
            target_offset=_uint(fields[21], "target offset"),
        )
        if (
            record.expected_outer != 50
            or record.expected_inner != 16_384
            or record.verifier_offset != record.parent_target_bytes
            or record.return_start + 9 != record.error_offset
            or record.process_target_bytes <= record.parent_target_bytes
            or record.process_target_bytes > MAX_TARGET_BYTES
            or record.elf_bytes > MAX_ELF_BYTES
        ):
            raise ProcessReplayError(f"{expected_name} contract envelope is inconsistent")
        records.append(record)
    seal_fields = lines[cursor].split("\t")
    if len(seal_fields) != 2 or seal_fields[0] != "seal":
        raise ProcessReplayError("WP5E contract seal row is malformed")
    seal = _hash(seal_fields[1], "contract seal")
    body = b"".join(line.encode() + b"\n" for line in lines[:cursor])
    if _sha256(CONTRACT_DOMAIN + body) != seal:
        raise ProcessReplayError("WP5E contract seal verification failed")
    return Contract(tuple(records), seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    if path.is_symlink() or not path.is_file():
        raise ProcessReplayError("WP5E authority is not a regular file")
    raw = path.read_bytes()
    lines = _canonical(raw, "WP5E authority", 32_000)
    expected_rows = 1 + len(AUTHORITY_METADATA) + 2 + len(EXPECTED_FILES) + 1
    if len(lines) != expected_rows or lines[0] != AUTHORITY_MAGIC:
        raise ProcessReplayError("WP5E authority shape or magic drifted")
    cursor = 1
    for key, value in AUTHORITY_METADATA:
        if lines[cursor] != f"meta\t{key}\t{value}":
            raise ProcessReplayError(f"WP5E authority metadata `{key}` drifted")
        cursor += 1
    if lines[cursor] != (
        f"component\tresidual-process-contract\t"
        f"distribution/s4-performance/WP5E-PROCESS.tsv\t{contract_seal}"
    ):
        raise ProcessReplayError("WP5E authority contract binding drifted")
    cursor += 1
    if lines[cursor] != (
        f"parent\tresidual-elf64-authority\t"
        f"distribution/s4-performance/WP5D-AUTHORITY.tsv\t{WP5D_AUTHORITY_SEAL}"
    ):
        raise ProcessReplayError("WP5E parent authority binding drifted")
    cursor += 1
    files: list[FileRecord] = []
    for expected_path in EXPECTED_FILES:
        fields = lines[cursor].split("\t")
        cursor += 1
        if (
            len(fields) != 5
            or fields[0] != "file"
            or MODE_RE.fullmatch(fields[1]) is None
            or PATH_RE.fullmatch(fields[4]) is None
            or fields[4] != expected_path
        ):
            raise ProcessReplayError("WP5E authority file order or shape drifted")
        files.append(
            FileRecord(
                mode=int(fields[1], 8),
                size=_uint(fields[2], "authority file size"),
                sha256=_hash(fields[3], "authority file hash"),
                path=fields[4],
            )
        )
    seal_fields = lines[cursor].split("\t")
    if len(seal_fields) != 2 or seal_fields[0] != "seal":
        raise ProcessReplayError("WP5E authority seal row is malformed")
    seal = _hash(seal_fields[1], "authority seal")
    body = b"".join(line.encode() + b"\n" for line in lines[:cursor])
    if _sha256(AUTHORITY_DOMAIN + body) != seal:
        raise ProcessReplayError("WP5E authority seal verification failed")
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    if tuple(record.path for record in authority.files) != EXPECTED_FILES:
        raise ProcessReplayError("WP5E authority file set drifted")
    for record in authority.files:
        path = root / record.path
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ProcessReplayError(f"authority path is not a regular file: {record.path}")
        mode = stat.S_IFREG | stat.S_IMODE(metadata.st_mode)
        raw = path.read_bytes()
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise ProcessReplayError(f"authority file drifted: {record.path}")


def _verify_source_boundary(root: Path) -> None:
    support = (root / "naux-lang/examples/support/s4_residual_process_elf.rs").read_text()
    example = (root / "naux-lang/examples/naux_s4_residual_process.rs").read_text()
    lowered = (support + "\n" + example).lower()
    for token in FORBIDDEN_EMITTER_SOURCE:
        if token in lowered:
            raise ProcessReplayError(f"WP5E emitter contains forbidden token `{token}`")
    for _, kernel, oracle in EXPECTED_KERNELS:
        if kernel in support:
            raise ProcessReplayError("generic completion support contains kernel-name dispatch")
        decimal_forms = {str(oracle), f"{oracle:_}"}
        if any(form in support or form in example for form in decimal_forms):
            raise ProcessReplayError("checksum oracle literal leaked into the Rust generator")
    required = (
        "append_completion_witness",
        "verify_process_target",
        "build_process_elf64",
        "verify_process_elf64",
        "SYS_WRITE",
        "RESULT_MAGIC",
    )
    if any(token not in support for token in required):
        raise ProcessReplayError("WP5E generic completion boundary is incomplete")


def _load(modrm: int, displacement: int) -> bytes:
    return bytes((0x48, 0x8B, modrm)) + struct.pack("<i", displacement)


def _patch_rel32(data: bytearray, displacement: int, target: int) -> None:
    next_offset = displacement + 4
    delta = target - next_offset
    if not -(1 << 31) <= delta < (1 << 31) or displacement < 0 or next_offset > len(data):
        raise ProcessReplayError("rel32 patch escapes the admitted byte stream")
    data[displacement:next_offset] = struct.pack("<i", delta)


def _emit_rel32(data: bytearray, opcode: bytes, target: int) -> None:
    data.extend(opcode)
    displacement = len(data)
    data.extend(b"\0\0\0\0")
    _patch_rel32(data, displacement, target)


def _mov_r8(value: int) -> bytes:
    return b"\x49\xb8" + struct.pack("<Q", value)


def _reconstruct_process_target(record: ContractRecord, parent: bytes) -> bytes:
    start = record.return_start
    end = start + 9
    expected_return = _load(0x85, record.checksum_displacement) + b"\xc9\xc3"
    if (
        record.verifier_offset != len(parent)
        or end != record.error_offset
        or parent[start:end] != expected_return
        or parent[record.error_offset:record.error_offset + 14]
        != b"\xbf\x46\0\0\0\xb8\x3c\0\0\0\x0f\x05\x0f\x0b"
    ):
        raise ProcessReplayError(f"{record.name} parent completion return drifted")
    result = bytearray(parent)
    result[start] = 0xE9
    _patch_rel32(result, start + 1, len(parent))
    result[start + 5:end] = b"\x90" * 4
    result.extend(_load(0x85, record.checksum_displacement))
    result.extend(_load(0x8D, record.outer_displacement))
    result.extend(_mov_r8(record.expected_outer))
    result.extend(b"\x4c\x39\xc1")
    _emit_rel32(result, b"\x0f\x85", record.error_offset)
    result.extend(_load(0x95, record.inner_displacement))
    result.extend(_mov_r8(record.expected_inner))
    result.extend(b"\x4c\x39\xc2")
    _emit_rel32(result, b"\x0f\x85", record.error_offset)
    result.extend(_load(0xB5, record.owner_displacement))
    result.extend(b"\x48\x85\xf6")
    _emit_rel32(result, b"\x0f\x85", record.error_offset)
    result.extend(b"\xc9\xc3")
    return bytes(result)


def _startup(ordinal: int, target_offset: int) -> bytes:
    result = bytearray(b"\xe8\0\0\0\0")
    call_delta = target_offset - (ELF_ENTRY_OFFSET + 5)
    if not -(1 << 31) <= call_delta < (1 << 31):
        raise ProcessReplayError("process target exceeds call rel32")
    result[1:5] = struct.pack("<i", call_delta)
    result.extend(b"\x48\x83\xec" + bytes((RESULT_BYTES,)))
    result.extend(_mov_r8(int.from_bytes(RESULT_MAGIC, "little")))
    result.extend(b"\x4c\x89\x04\x24")
    result.extend(_mov_r8(ordinal))
    result.extend(b"\x4c\x89\x44\x24\x08")
    result.extend(b"\x48\x89\x44\x24\x10")
    result.extend(b"\x48\x89\x4c\x24\x18")
    result.extend(b"\x48\x89\x54\x24\x20")
    result.extend(b"\x48\x89\x74\x24\x28")
    result.extend(b"\xb8" + struct.pack("<I", 1))
    result.extend(b"\xbf" + struct.pack("<I", 1))
    result.extend(b"\x48\x89\xe6")
    result.extend(b"\xba" + struct.pack("<I", RESULT_BYTES))
    result.extend(b"\x0f\x05\x48\x83\xf8" + bytes((RESULT_BYTES,)))
    failure_displacement = len(result) + 2
    result.extend(b"\x0f\x85\0\0\0\0")
    result.extend(b"\x48\x83\xc4" + bytes((RESULT_BYTES,)))
    result.extend(b"\x31\xff\xb8" + struct.pack("<I", 60) + b"\x0f\x05\x0f\x0b")
    failure = len(result)
    result.extend(
        b"\xbf"
        + struct.pack("<I", FAILURE_EXIT_CODE)
        + b"\xb8"
        + struct.pack("<I", 60)
        + b"\x0f\x05\x0f\x0b"
    )
    _patch_rel32(result, failure_displacement, failure)
    return bytes(result)


def _elf_header(image_bytes: int) -> bytes:
    identity = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\0" * 8
    header = identity + struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        62,
        1,
        ELF_ENTRY,
        64,
        0,
        0,
        64,
        56,
        2,
        0,
        0,
        0,
    )
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, ELF_BASE, ELF_BASE, image_bytes, image_bytes, 4096)
    stack = struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
    return header + load + stack


def _reconstruct_elf(record: ContractRecord, target: bytes) -> bytes:
    provisional = _startup(record.ordinal, 0)
    target_offset = (ELF_ENTRY_OFFSET + len(provisional) + TARGET_ALIGNMENT - 1) & -TARGET_ALIGNMENT
    startup = _startup(record.ordinal, target_offset)
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
        raise ProcessReplayError(f"{record.name} ELF layout receipt drifted")
    return bytes(result)


def _verify_kernel(kernel: Kernel) -> None:
    record = kernel.record
    if (
        len(kernel.parent_target) != record.parent_target_bytes
        or len(kernel.process_target) != record.process_target_bytes
        or len(kernel.elf) != record.elf_bytes
        or _sha256(kernel.parent_target) != record.parent_target_hash
        or _sha256(kernel.process_target) != record.process_target_hash
        or _sha256(kernel.elf) != record.elf_hash
    ):
        raise ProcessReplayError(f"{record.name} artifact hash or extent drifted")
    if kernel.process_target != _reconstruct_process_target(record, kernel.parent_target):
        raise ProcessReplayError(f"{record.name} completion appendix reconstruction differs")
    if kernel.elf != _reconstruct_elf(record, kernel.process_target):
        raise ProcessReplayError(f"{record.name} ELF reconstruction differs")
    if kernel.elf[:7] != b"\x7fELF\x02\x01\x01" or struct.unpack_from("<HH", kernel.elf, 16) != (2, 62):
        raise ProcessReplayError(f"{record.name} is not an x86-64 ET_EXEC image")
    if struct.unpack_from("<I", kernel.elf, 68)[0] != 5 or struct.unpack_from("<I", kernel.elf, 124)[0] != 6:
        raise ProcessReplayError(f"{record.name} load or stack permissions drifted")
    oracle = struct.pack("<q", record.oracle)
    if oracle in kernel.process_target or oracle in kernel.elf[:record.target_offset]:
        raise ProcessReplayError(f"{record.name} checksum oracle leaked into the artifact")


def parse_candidate(raw: bytes, contract: Contract) -> Candidate:
    lines = _canonical(raw, "WP5E candidate", MAX_CANDIDATE_BYTES)
    expected_rows = 1 + len(META_ROWS) + 1 + len(EXPECTED_KERNELS) * 4 + 1
    if len(lines) != expected_rows or lines[0] != CANDIDATE_MAGIC:
        raise ProcessReplayError("WP5E candidate shape or magic drifted")
    cursor = 1
    for row in META_ROWS:
        if lines[cursor] != row:
            raise ProcessReplayError("WP5E candidate metadata drifted")
        cursor += 1
    if lines[cursor] != COLUMNS:
        raise ProcessReplayError("WP5E candidate columns drifted")
    cursor += 1
    kernels: list[Kernel] = []
    for record in contract.records:
        fields = lines[cursor].split("\t")
        cursor += 1
        if len(fields) != 18 or fields[:3] != ["kernel", f"{record.ordinal:02}", record.name]:
            raise ProcessReplayError("WP5E candidate kernel row is malformed")
        observed = (
            fields[3],
            _uint(fields[4], "parent target bytes"),
            _uint(fields[5], "process target bytes"),
            _uint(fields[6], "error offset"),
            _uint(fields[7], "return start"),
            _uint(fields[8], "verifier offset"),
            _int(fields[9], "checksum displacement"),
            _int(fields[10], "outer displacement"),
            _int(fields[11], "inner displacement"),
            _int(fields[12], "owner displacement"),
            _uint(fields[13], "expected outer"),
            _uint(fields[14], "expected inner"),
            _uint(fields[15], "ELF bytes"),
            _uint(fields[16], "startup bytes"),
            _uint(fields[17], "target offset"),
        )
        expected = (
            record.work_hash,
            record.parent_target_bytes,
            record.process_target_bytes,
            record.error_offset,
            record.return_start,
            record.verifier_offset,
            record.checksum_displacement,
            record.outer_displacement,
            record.inner_displacement,
            record.owner_displacement,
            record.expected_outer,
            record.expected_inner,
            record.elf_bytes,
            record.startup_bytes,
            record.target_offset,
        )
        if observed != expected:
            raise ProcessReplayError(f"{record.name} candidate receipt drifted")
        payloads: list[bytes] = []
        for label in ("parent-target-hex", "target-hex", "elf-hex"):
            payload_fields = lines[cursor].split("\t")
            cursor += 1
            if len(payload_fields) != 3 or payload_fields[:2] != [label, f"{record.ordinal:02}"]:
                raise ProcessReplayError(f"{record.name} {label} row drifted")
            try:
                payload = bytes.fromhex(payload_fields[2])
            except ValueError as error:
                raise ProcessReplayError(f"{record.name} {label} is not hex") from error
            if payload.hex() != payload_fields[2]:
                raise ProcessReplayError(f"{record.name} {label} is not canonical lowercase")
            payloads.append(payload)
        kernel = Kernel(record, payloads[0], payloads[1], payloads[2])
        _verify_kernel(kernel)
        kernels.append(kernel)
    if cursor != len(lines) - 1 or lines[cursor] != "verification\tregenerated":
        raise ProcessReplayError("WP5E candidate has trailing or missing rows")
    return Candidate(tuple(kernels), raw)


def _report(
    contract: Contract,
    authority: Authority,
    candidate: Candidate | None,
    results: tuple[ProcessResult, ...] = (),
) -> bytes:
    rows = [
        REPORT_MAGIC,
        f"parent-contract\t{WP5D_CONTRACT_SEAL}",
        f"parent-authority\t{WP5D_AUTHORITY_SEAL}",
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        "status\tfresh-process-checksum-work-parity-admitted",
        "claim-status\tuntimed-parity-only",
        "timing-status\tforbidden",
        "kernels\t4",
    ]
    if candidate is None:
        rows.extend(("mode\tstatic-authority", "replays\t0"))
    else:
        rows.extend(
            (
                "mode\tuntimed-fresh-process-replay",
                "replays\t2",
                f"candidate\t{_sha256(candidate.raw)}",
                f"target-aggregate\t{_sha256(''.join(k.record.process_target_hash for k in candidate.kernels).encode())}",
                f"elf-aggregate\t{_sha256(''.join(k.record.elf_hash for k in candidate.kernels).encode())}",
            )
        )
        for result in results:
            rows.append(
                f"result\t{result.pass_number}\t{result.ordinal:02}\t{result.name}\t"
                f"{result.checksum}\t{result.outer}\t{result.inner}\t{result.owner}"
            )
    body = b"".join(row.encode() + b"\n" for row in rows)
    return body + f"report-root\t{_sha256(REPORT_DOMAIN + body)}\n".encode()


def validate(root: Path) -> Admission:
    parent = wp5d.validate(root)
    if parent.contract.seal != WP5D_CONTRACT_SEAL or parent.authority.seal != WP5D_AUTHORITY_SEAL:
        raise ProcessReplayError("WP5D parent authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP5E-PROCESS.tsv")
    wp5d_records = parent.contract.records
    if tuple(record.parent_target_hash for record in contract.records) != tuple(
        record.target_hash for record in wp5d_records
    ):
        raise ProcessReplayError("WP5E parent target hashes differ from WP5D")
    authority = parse_authority(
        root / "distribution/s4-performance/WP5E-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_source_boundary(root)
    report = _report(contract, authority, None)
    root_hash = report.decode().split("report-root\t", 1)[1].strip()
    return Admission(contract, authority, report, root_hash)


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
        raise ProcessReplayError("reviewed WP5E emitter is not a regular executable")
    if binary.name != "naux_s4_residual_process":
        raise ProcessReplayError("reviewed WP5E emitter has a noncanonical filename")
    if _looks_like_generated_image(binary):
        raise ProcessReplayError("refusing to use a generated process image as the WP5E emitter")


def _run_emitter(binary: Path) -> subprocess.CompletedProcess[bytes]:
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C"}
    return subprocess.run(
        [os.fspath(binary)],
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
        timeout=30,
    )


def _write_exact_image(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o700)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ProcessReplayError("artifact write made no progress")
            view = view[written:]
        os.fchmod(descriptor, 0o700)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ProcessReplayError("materialized artifact identity drifted")
    if _sha256(path.read_bytes()) != _sha256(payload):
        raise ProcessReplayError("materialized artifact readback drifted")


def _run_process_image(path: Path, expected_hash: str) -> subprocess.CompletedProcess[bytes]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ProcessReplayError("WP5E process image is not an owned regular file")
    raw = path.read_bytes()
    if _sha256(raw) != expected_hash or not _looks_like_generated_image(path):
        raise ProcessReplayError("WP5E process image failed exact pre-execution admission")
    return subprocess.run(
        [os.fspath(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.fspath(path.parent),
        env={"LC_ALL": "C", "LANG": "C"},
        check=False,
        timeout=30,
    )


def _parse_result(
    completed: subprocess.CompletedProcess[bytes],
    record: ContractRecord,
    pass_number: int,
) -> ProcessResult:
    if completed.returncode != 0 or completed.stderr or len(completed.stdout) != RESULT_BYTES:
        raise ProcessReplayError(f"{record.name} fresh process did not complete exactly")
    magic, ordinal, checksum, outer, inner, owner = RESULT_STRUCT.unpack(completed.stdout)
    if (
        magic != RESULT_MAGIC
        or ordinal != record.ordinal
        or checksum != record.oracle
        or outer != record.expected_outer
        or inner != record.expected_inner
        or owner != 0
    ):
        raise ProcessReplayError(f"{record.name} checksum or terminal work state differs")
    return ProcessResult(pass_number, record.ordinal, record.name, checksum, outer, inner, owner)


def replay(admission: Admission, binary: Path) -> tuple[bytes, Candidate, tuple[ProcessResult, ...]]:
    _validate_emitter_binary(binary)
    reviewed_binary = binary.resolve(strict=True)
    first = _run_emitter(reviewed_binary)
    second = _run_emitter(reviewed_binary)
    for completed in (first, second):
        if completed.returncode != 0 or completed.stderr:
            raise ProcessReplayError("WP5E emitter did not exit cleanly and silently")
    if first.stdout != second.stdout:
        raise ProcessReplayError("WP5E emitter is nondeterministic")
    candidate = parse_candidate(first.stdout, admission.contract)
    results: list[ProcessResult] = []
    with tempfile.TemporaryDirectory(prefix="naux-wp5e-process-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        for pass_number in (1, 2):
            for kernel in candidate.kernels:
                path = root / f"pass-{pass_number}-artifact-{kernel.record.ordinal:02}"
                _write_exact_image(path, kernel.elf)
                completed = _run_process_image(path, kernel.record.elf_hash)
                results.append(_parse_result(completed, kernel.record, pass_number))
    result_tuple = tuple(results)
    return _report(admission.contract, admission.authority, candidate, result_tuple), candidate, result_tuple


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
            report, _, _ = replay(admission, arguments.binary)
            sys.stdout.buffer.write(report)
    except (
        ProcessReplayError,
        wp5d.Elf64Error,
        OSError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"S4-WP5E validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
