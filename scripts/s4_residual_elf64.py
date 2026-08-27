#!/usr/bin/env python3
"""Validate and independently replay the clock-free S4-WP5D ELF64 boundary."""

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

import s4_residual_machine_ir as wp5c


CONTRACT_MAGIC = "NAUX-S4-RESIDUAL-ELF64-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-RESIDUAL-ELF64-AUTHORITY\t1"
CANDIDATE_MAGIC = "NAUX-S4-RESIDUAL-ELF64\t1"
REPORT_MAGIC = "NAUX-S4-RESIDUAL-ELF64-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-residual-elf64:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-residual-elf64:authority:v1\0"
PLAN_DOMAIN = b"NAUX:s4-residual-x64:plan:v1\0"
MAPPING_DOMAIN = b"NAUX:s4-residual-x64:mapping:v1\0"
REPORT_DOMAIN = b"NAUX:s4-residual-elf64:report:v1\0"
WP5C_AUTHORITY_SEAL = "bcb4aab033397092049e9fcaf32aba9e615d3029789dafdc2dfb32ea3324860f"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
HOME_RE = re.compile(r"([sr])(0|[1-9][0-9]*):(unit|bool|i64|owned-list-i64)@-([1-9][0-9]*)\Z")
BLOCK_RE = re.compile(r"b(0|[1-9][0-9]*)\Z")
MAX_CANDIDATE_BYTES = 512_000
MAX_TARGET_BYTES = 1_048_576
MAX_ELF_BYTES = 1_114_112
ELF_BASE = 0x0040_0000
ELF_ENTRY_OFFSET = 0x100
ELF_ENTRY = ELF_BASE + ELF_ENTRY_OFFSET
TARGET_OFFSET = 0x110

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-authority", WP5C_AUTHORITY_SEAL),
    ("status", "x86-64-elf64-structurally-admitted"),
    ("execution-status", "forbidden"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("dataset", "static-n16384-r50"),
    ("input-ir", "closed-wp5c-v1"),
    ("target-plan", "stack-home-x86-64-v1"),
    ("elf-format", "sectionless-et-exec-rx-load-rw-nx-stack-v1"),
    ("pipeline", "single-machine-ir-to-x86-64-elf64-lowering"),
    ("kernel-count", "4"),
    ("linker", "none"),
    ("libc", "none"),
    ("allowed-syscalls", "mmap-munmap-exit"),
    ("correspondence", "exact-machine-operation-to-byte-range"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP5D"),
    ("authority-id", "s4-residual-elf64-v1"),
    ("status", "x86-64-elf64-structurally-admitted"),
    ("execution-status", "forbidden"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("kernel-count", "4"),
    ("file-count", "8"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-residual-elf64.yml",
    "distribution/s4-performance/WP5D-NONCLAIMS.md",
    "distribution/s4-performance/WP5D-README.md",
    "distribution/s4-performance/WP5D-ELF64.tsv",
    "naux-lang/examples/naux_s4_residual_elf64.rs",
    "naux-lang/examples/support/s4_residual_x64_elf.rs",
    "scripts/s4_residual_elf64.py",
    "scripts/tests/test_s4_residual_elf64.py",
)
EXPECTED_KERNELS = (
    (
        "01", "sum-dense",
        "97d8699e9449d53f4f3c9386839099be194b7db985709122092dfac3eacb8f2d",
        "08fdc00ae485b2365b9f7f60879234a19d0341a089f9b4c350528fa16383f98a",
        "6e20cd38880cecb4a37532735d9c1cad84dc6b79eec5432b6fbf0a7fd62d2df8",
        "71b739fe8fdddcf7b55dbdb5a7f09547f0c5360dd94b5bbdbb4a1988afb347f0",
        "55d6990b4a5f8395ab08e6df2e7bfe6ed742803ed9bee191a49613f971f50cdc",
        "288", "7", "43", "7", "48", "993", "979", "1265", "272",
    ),
    (
        "02", "branch-mix",
        "8095c962d36b2a6876770412feac0df8fdd5f4e3627481f97f6b78f9bc489888",
        "91aa7f951f09f2469f3d32ead41292010e3e0f9d4d73cbf789fc4483bf55ec5c",
        "ab9b853e71b7ac1675446affa9d02e16f514bb0bbb9ca688f3d3361981da620d",
        "cc8ba64dd6c4301e0d025f309c8ffa2c2eb40fc06cc7743b627e621159310c69",
        "2986151e2a777c6cc00eaaeabbd7e3452e61e40b39d4006eecdcc0924aa3bf15",
        "352", "12", "50", "12", "58", "1188", "1174", "1460", "272",
    ),
    (
        "03", "dot-product",
        "b2fa698b60cb29e50d14e7f56650d1f09657562e3160e99bc7930e60f7c9e857",
        "d0d5bbb4a107c75c52777cd7df315e9c97169cfec5900dc869b94378662efb87",
        "b11082e8f079692a34559ba979dfd95e29da232ffbc85ad543b37d44e2a3271d",
        "bc9c80772b14a43181ec64ba698fbe77c63e59a4cb9674fa6b8ad271d9557f7e",
        "cd925a1f2edd5f9334874f352f420cf33437151262107dc65f2bc510eb780a96",
        "288", "7", "41", "7", "46", "950", "936", "1222", "272",
    ),
    (
        "04", "list-update",
        "c6ac1a97cad0ec0529e7f5f49bb91d316fa63a2b9abb2c7452a0040fe4150199",
        "35c329d01d5a019c89c9134f91b75467b52e85ff7a33346671125b2261ffcebf",
        "b7ba7ad25cf0209c355074130032c3b37adc8fe35cae4a926b4c5ff8103ad336",
        "5c1661aef5731cf1646f4a3e7488b038040bc9f979fe5be2e3b0e2b315b07f39",
        "bd7f4842eee1b970b7bfab7551cf5959ccce937388163161b9643f717c0740ef",
        "336", "7", "46", "7", "51", "1071", "1057", "1343", "272",
    ),
)
COLUMNS = (
    "columns\tordinal\tkernel\tmachine-hash\tframe-bytes\tblock-count\t"
    "operation-count\tterminator-count\tmapping-count\ttarget-bytes\terror-offset\telf-bytes\ttarget-offset"
)
META_ROWS = (
    "meta\tstatus\tx86-64-elf64-structurally-admitted",
    "meta\texecution-status\tforbidden",
    "meta\ttiming-status\tforbidden",
    "meta\tlinker\tnone",
    "meta\tlibc\tnone",
    "meta\ttarget\tx86_64-unknown-linux-gnu",
)
FORBIDDEN_SOURCE = (
    "instant::", "systemtime::", ".elapsed()", "duration_since(",
    "runtime_ns", "compile_ns", "runtime-ns", "compile-ns", "command::new",
    "gcc", "clang", "cc::", "ld ", "objcopy", "throughput", "latency", "median",
)


class Elf64Error(RuntimeError):
    """A fail-closed S4-WP5D validation error."""


@dataclass(frozen=True)
class ContractRecord:
    ordinal: int
    name: str
    machine_hash: str
    plan_hash: str
    target_hash: str
    elf_hash: str
    mapping_hash: str
    frame_bytes: int
    block_count: int
    operation_count: int
    terminator_count: int
    mapping_count: int
    target_bytes: int
    error_offset: int
    elf_bytes: int
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
class Block:
    block_id: int
    operations: tuple[tuple[str, ...], ...]
    terminator: tuple[str, ...]


@dataclass(frozen=True)
class Encoding:
    block: int
    ordinal: int
    kind: str
    start: int
    end: int


@dataclass(frozen=True)
class Mapping:
    residual_ip: int
    block: int
    machine_ordinal: int
    kind: str


@dataclass(frozen=True)
class Kernel:
    record: ContractRecord
    blocks: tuple[Block, ...]
    encodings: tuple[Encoding, ...]
    mappings: tuple[Mapping, ...]
    target: bytes
    elf: bytes


@dataclass(frozen=True)
class Candidate:
    kernels: tuple[Kernel, ...]
    raw: bytes


@dataclass(frozen=True)
class Admission:
    contract: Contract
    authority: Authority
    report: bytes
    report_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(raw: bytes, label: str, limit: int = 8_000_000) -> list[str]:
    if not raw or len(raw) > limit or not raw.endswith(b"\n"):
        raise Elf64Error(f"{label} has invalid extent")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Elf64Error(f"{label} is not UTF-8") from error
    if "\r" in text or "\x00" in text:
        raise Elf64Error(f"{label} is not canonical LF text")
    lines = text.splitlines()
    if any(not line for line in lines):
        raise Elf64Error(f"{label} contains a blank row")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    lines = _canonical(path.read_bytes(), path.as_posix())
    if len(lines) < 3 or lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise Elf64Error(f"unsupported sealed document: {path}")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise Elf64Error(f"invalid terminal seal: {path}")
    body = "".join(f"{line}\n" for line in lines[:-1]).encode()
    if _sha256(domain + body) != fields[1]:
        raise Elf64Error(f"seal mismatch: {path}")
    return lines[1:-1], fields[1]


def _uint(value: str, label: str, maximum: int = (1 << 64) - 1) -> int:
    if not UINT_RE.fullmatch(value) or int(value) > maximum:
        raise Elf64Error(f"invalid unsigned integer in {label}")
    return int(value)


def _hash(value: str, label: str) -> str:
    if not HASH_RE.fullmatch(value):
        raise Elf64Error(f"invalid SHA-256 in {label}")
    return value


def _ordinal(value: str, label: str) -> int:
    if value not in ("01", "02", "03", "04"):
        raise Elf64Error(f"invalid ordinal in {label}")
    return int(value)


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if len(rows) != len(CONTRACT_METADATA) + 4:
        raise Elf64Error("unexpected WP5D contract extent")
    metadata = []
    for row in rows[: len(CONTRACT_METADATA)]:
        fields = row.split("\t")
        if len(fields) != 3 or fields[0] != "meta":
            raise Elf64Error("invalid WP5D contract metadata")
        metadata.append((fields[1], fields[2]))
    if tuple(metadata) != CONTRACT_METADATA:
        raise Elf64Error("WP5D contract metadata drifted")
    records = []
    for expected, row in zip(EXPECTED_KERNELS, rows[len(CONTRACT_METADATA) :]):
        fields = row.split("\t")
        if len(fields) != 17 or fields[0] != "kernel" or tuple(fields[1:]) != expected:
            raise Elf64Error("WP5D kernel identity drifted")
        records.append(ContractRecord(
            _ordinal(fields[1], "contract ordinal"), fields[2],
            *(_hash(value, "contract hash") for value in fields[3:8]),
            *(_uint(value, "contract count", MAX_ELF_BYTES) for value in fields[8:17]),
        ))
    return Contract(tuple(records), seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    if len(rows) != len(AUTHORITY_METADATA) + 2 + len(EXPECTED_FILES):
        raise Elf64Error("unexpected WP5D authority extent")
    metadata = []
    for row in rows[: len(AUTHORITY_METADATA)]:
        fields = row.split("\t")
        if len(fields) != 3 or fields[0] != "meta":
            raise Elf64Error("invalid WP5D authority metadata")
        metadata.append((fields[1], fields[2]))
    if tuple(metadata) != AUTHORITY_METADATA:
        raise Elf64Error("WP5D authority metadata drifted")
    if rows[len(AUTHORITY_METADATA)].split("\t") != [
        "component", "residual-elf64-contract",
        "distribution/s4-performance/WP5D-ELF64.tsv", contract_seal,
    ]:
        raise Elf64Error("WP5D contract component drifted")
    if rows[len(AUTHORITY_METADATA) + 1].split("\t") != [
        "parent", "residual-machine-ir-authority",
        "distribution/s4-performance/WP5C-AUTHORITY.tsv", WP5C_AUTHORITY_SEAL,
    ]:
        raise Elf64Error("WP5D parent authority drifted")
    files = []
    for expected, row in zip(EXPECTED_FILES, rows[len(AUTHORITY_METADATA) + 2 :]):
        fields = row.split("\t")
        if len(fields) != 5 or fields[0] != "file" or fields[4] != expected:
            raise Elf64Error("WP5D file inventory drifted")
        if not MODE_RE.fullmatch(fields[1]) or not PATH_RE.fullmatch(fields[4]):
            raise Elf64Error("invalid WP5D authority file row")
        files.append(FileRecord(
            int(fields[1], 8), _uint(fields[2], "file size"),
            _hash(fields[3], "file hash"), fields[4],
        ))
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    if tuple(record.path for record in authority.files) != EXPECTED_FILES:
        raise Elf64Error("WP5D authority does not bind the exact file set")
    for record in authority.files:
        path = root / record.path
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            raise Elf64Error(f"WP5D file is not regular: {record.path}")
        raw = path.read_bytes()
        mode = stat.S_IFREG | stat.S_IMODE(info.st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise Elf64Error(f"WP5D file drifted: {record.path}")


def _verify_source_boundary(root: Path) -> None:
    support = (root / "naux-lang/examples/support/s4_residual_x64_elf.rs").read_text().lower()
    for name in ("sum-dense", "branch-mix", "dot-product", "list-update"):
        if name in support:
            raise Elf64Error("generic target lowering dispatches on a kernel identity")
    combined = b"".join((root / path).read_bytes().lower() for path in (
        "naux-lang/examples/naux_s4_residual_elf64.rs",
        "naux-lang/examples/support/s4_residual_x64_elf.rs",
    ))
    for token in FORBIDDEN_SOURCE:
        if token.encode() in combined:
            raise Elf64Error(f"WP5D source contains forbidden token: {token}")


def _home(value: str, expected_type: str | None = None) -> tuple[str, int, str, int]:
    match = HOME_RE.fullmatch(value)
    if match is None:
        raise Elf64Error("invalid stack-home syntax")
    kind, index, value_type, displacement = match.groups()
    if expected_type is not None and value_type != expected_type:
        raise Elf64Error("stack-home type drifted")
    displacement_value = int(displacement)
    if displacement_value % 8 != 0:
        raise Elf64Error("stack home is not eight-byte aligned")
    return kind, int(index), value_type, displacement_value


def _verify_operation(fields: tuple[str, ...], frame_bytes: int) -> None:
    opcode = fields[0]
    arity = {
        "const-i64": 3, "copy": 3, "store-slot": 3, "add-slot-const": 3,
        "i64-add": 4, "i64-sub": 4, "i64-mul": 4,
        "i64-eq": 4, "i64-ne": 4, "i64-gt": 4, "i64-ge": 4,
        "i64-lt": 4, "i64-le": 4, "range-allocate-init": 3,
        "list-length-static": 3, "list-load-checked": 5,
        "list-store-checked": 6, "release-owned-list": 3,
    }.get(opcode)
    if arity is None or len(fields) != arity:
        raise Elf64Error(f"unsupported or malformed target operation: {opcode}")
    homes = [field for field in fields[1:] if HOME_RE.fullmatch(field)]
    for value in homes:
        if _home(value)[3] > frame_bytes:
            raise Elf64Error("target operation home escapes the frame")
    if opcode == "const-i64":
        int(fields[2])
    elif opcode == "copy" and _home(fields[1])[2] != _home(fields[2])[2]:
        raise Elf64Error("copy changes type")
    elif opcode == "store-slot":
        if _home(fields[1])[0] != "s" or _home(fields[1])[2] != _home(fields[2])[2]:
            raise Elf64Error("store-slot home or type drifted")
    elif opcode == "add-slot-const":
        _home(fields[1], "i64")
        int(fields[2])
    elif opcode.startswith("i64-"):
        result_type = "bool" if opcode[4:] in {"eq", "ne", "gt", "ge", "lt", "le"} else "i64"
        _home(fields[1], result_type)
        _home(fields[2], "i64")
        _home(fields[3], "i64")
    elif opcode == "range-allocate-init":
        _home(fields[1], "owned-list-i64")
        if _uint(fields[2], "list length") != 16_384:
            raise Elf64Error("allocation length drifted")
    elif opcode == "list-length-static":
        _home(fields[1], "i64")
        if _uint(fields[2], "list length") != 16_384:
            raise Elf64Error("static list length drifted")
    elif opcode == "list-load-checked":
        _home(fields[1], "i64"); _home(fields[2], "owned-list-i64"); _home(fields[3], "i64")
        if _uint(fields[4], "list length") != 16_384:
            raise Elf64Error("load bound drifted")
    elif opcode == "list-store-checked":
        _home(fields[1], "unit"); _home(fields[2], "owned-list-i64")
        _home(fields[3], "i64"); _home(fields[4], "i64")
        if _uint(fields[5], "list length") != 16_384:
            raise Elf64Error("store bound drifted")
    elif opcode == "release-owned-list":
        if _home(fields[1], "owned-list-i64")[0] != "s" or _uint(fields[2], "release length") != 16_384:
            raise Elf64Error("release owner or length drifted")


def _verify_terminator(fields: tuple[str, ...], block_count: int, frame_bytes: int) -> None:
    if fields[0] == "goto" and len(fields) == 2:
        targets = fields[1:]
    elif fields[0] == "branch" and len(fields) == 4:
        if _home(fields[1], "bool")[3] > frame_bytes:
            raise Elf64Error("branch home escapes the frame")
        targets = fields[2:]
    elif fields[0] == "return" and len(fields) == 2:
        if _home(fields[1], "i64")[3] > frame_bytes:
            raise Elf64Error("return home escapes the frame")
        return
    else:
        raise Elf64Error("unsupported target terminator")
    for target in targets:
        match = BLOCK_RE.fullmatch(target)
        if match is None or int(match.group(1)) >= block_count:
            raise Elf64Error("terminator target escapes the CFG")


def _verify_elf(elf: bytes, target: bytes, record: ContractRecord) -> None:
    if len(elf) != record.elf_bytes or len(elf) > MAX_ELF_BYTES:
        raise Elf64Error("ELF extent drifted")
    if elf[:16] != b"\x7fELF\x02\x01\x01" + b"\0" * 9:
        raise Elf64Error("ELF identity drifted")
    if struct.unpack_from("<HHIQQQIHHHHHH", elf, 16) != (
        2, 62, 1, ELF_ENTRY, 64, 0, 0, 64, 56, 2, 0, 0, 0,
    ):
        raise Elf64Error("ELF header drifted")
    if struct.unpack_from("<IIQQQQQQ", elf, 64) != (
        1, 5, 0, ELF_BASE, ELF_BASE, len(elf), len(elf), 4096,
    ):
        raise Elf64Error("ELF R-X load segment drifted")
    if struct.unpack_from("<IIQQQQQQ", elf, 120) != (
        0x6474E551, 6, 0, 0, 0, 0, 0, 16,
    ):
        raise Elf64Error("ELF RW-NX stack segment drifted")
    if any(elf[176:256]):
        raise Elf64Error("ELF header padding is not zero")
    startup = b"\xe8\x0b\0\0\0\x31\xff\xb8\x3c\0\0\0\x0f\x05\x0f\x0b"
    if elf[256:272] != startup or record.target_offset != TARGET_OFFSET:
        raise Elf64Error("ELF startup or target offset drifted")
    if elf[TARGET_OFFSET:] != target:
        raise Elf64Error("ELF target payload differs")


def _verify_kernel(kernel: Kernel) -> None:
    record = kernel.record
    if len(kernel.blocks) != record.block_count:
        raise Elf64Error("target block count drifted")
    plan_lines = []
    expected_encodings = []
    operation_count = 0
    for expected_id, block in enumerate(kernel.blocks):
        if block.block_id != expected_id:
            raise Elf64Error("target blocks are not contiguous")
        plan_lines.append(f"block\t{record.ordinal:02}\t{block.block_id}\t{len(block.operations)}\n")
        for ordinal, operation in enumerate(block.operations):
            _verify_operation(operation, record.frame_bytes)
            plan_lines.append(
                f"operation\t{record.ordinal:02}\t{block.block_id}\t{ordinal}\t"
                + "\t".join(operation) + "\n"
            )
            expected_encodings.append((block.block_id, ordinal, "operation"))
            operation_count += 1
        _verify_terminator(block.terminator, record.block_count, record.frame_bytes)
        plan_lines.append(
            f"terminator\t{record.ordinal:02}\t{block.block_id}\t"
            + "\t".join(block.terminator) + "\n"
        )
        expected_encodings.append((block.block_id, len(block.operations), "terminator"))
    if operation_count != record.operation_count:
        raise Elf64Error("target operation count drifted")
    plan_hash = _sha256(PLAN_DOMAIN + "".join(plan_lines).encode())
    if plan_hash != record.plan_hash:
        raise Elf64Error("target plan hash drifted")

    if len(kernel.encodings) != record.operation_count + record.terminator_count:
        raise Elf64Error("encoding range count drifted")
    if tuple((row.block, row.ordinal, row.kind) for row in kernel.encodings) != tuple(expected_encodings):
        raise Elf64Error("encoding ranges do not follow the target plan")
    expected_start = 11
    for row in kernel.encodings:
        if row.start != expected_start or row.end <= row.start or row.end > record.error_offset:
            raise Elf64Error("encoding ranges do not partition the target body")
        expected_start = row.end
    if expected_start != record.error_offset:
        raise Elf64Error("encoding ranges do not reach the error block")
    if len(kernel.target) != record.target_bytes or len(kernel.target) > MAX_TARGET_BYTES:
        raise Elf64Error("target byte extent drifted")
    if kernel.target[:7] != b"\x55\x48\x89\xe5\x48\x81\xec":
        raise Elf64Error("target prologue drifted")
    if struct.unpack_from("<I", kernel.target, 7)[0] != record.frame_bytes:
        raise Elf64Error("target frame immediate drifted")
    error = b"\xbf\x46\0\0\0\xb8\x3c\0\0\0\x0f\x05\x0f\x0b"
    if kernel.target[record.error_offset:] != error:
        raise Elf64Error("target fail-closed exit block drifted")
    if _sha256(kernel.target) != record.target_hash or _sha256(kernel.elf) != record.elf_hash:
        raise Elf64Error("target or ELF identity drifted")
    syscall_offsets = []
    cursor = 0
    while True:
        cursor = kernel.target.find(b"\x0f\x05", cursor)
        if cursor < 0:
            break
        syscall_offsets.append(cursor)
        cursor += 2
    for offset in syscall_offsets:
        if offset >= record.error_offset:
            continue
        owner = next((row for row in kernel.encodings if row.start <= offset < row.end), None)
        if owner is None:
            raise Elf64Error("syscall escapes an operation encoding range")
        operation = kernel.blocks[owner.block].operations[owner.ordinal][0]
        if operation not in ("range-allocate-init", "release-owned-list"):
            raise Elf64Error("unadmitted syscall entered target operation")
    if len(syscall_offsets) != 3:
        raise Elf64Error("target syscall cardinality drifted")
    _verify_elf(kernel.elf, kernel.target, record)

    if len(kernel.mappings) != record.mapping_count:
        raise Elf64Error("Machine IR mapping count drifted")
    mapping_rows = []
    for index, mapping in enumerate(kernel.mappings):
        if mapping.residual_ip != index:
            raise Elf64Error("Machine IR residual identities are not contiguous")
        if not any(
            row.block == mapping.block
            and row.ordinal == mapping.machine_ordinal
            and row.kind == mapping.kind
            for row in kernel.encodings
        ):
            raise Elf64Error("Machine IR correspondence does not name an encoding range")
        mapping_rows.append(
            f"correspondence\t{record.ordinal:02}\t{mapping.residual_ip}\t{mapping.block}\t"
            f"{mapping.machine_ordinal}\t{mapping.kind}\n"
        )
    if _sha256(MAPPING_DOMAIN + "".join(mapping_rows).encode()) != record.mapping_hash:
        raise Elf64Error("Machine IR correspondence hash drifted")


def parse_candidate(raw: bytes, contract: Contract) -> Candidate:
    lines = _canonical(raw, "WP5D candidate", MAX_CANDIDATE_BYTES)
    if lines[:8] != [CANDIDATE_MAGIC, *META_ROWS, COLUMNS] or lines[-1] != "verification\tregenerated":
        raise Elf64Error("candidate envelope drifted")
    cursor = 8
    kernels = []
    for record in contract.records:
        fields = lines[cursor].split("\t")
        expected_summary = [
            "kernel", f"{record.ordinal:02}", record.name, record.machine_hash,
            str(record.frame_bytes), str(record.block_count), str(record.operation_count),
            str(record.terminator_count), str(record.mapping_count), str(record.target_bytes),
            str(record.error_offset), str(record.elf_bytes), str(record.target_offset),
        ]
        if fields != expected_summary:
            raise Elf64Error("candidate kernel summary drifted")
        cursor += 1
        blocks = []
        for block_id in range(record.block_count):
            fields = lines[cursor].split("\t")
            if len(fields) != 4 or fields[:3] != ["block", f"{record.ordinal:02}", str(block_id)]:
                raise Elf64Error("candidate block row drifted")
            count = _uint(fields[3], "block operation count", 10_000)
            cursor += 1
            operations = []
            for ordinal in range(count):
                fields = lines[cursor].split("\t")
                if len(fields) < 6 or fields[:4] != [
                    "operation", f"{record.ordinal:02}", str(block_id), str(ordinal),
                ]:
                    raise Elf64Error("candidate operation row drifted")
                operations.append(tuple(fields[4:]))
                cursor += 1
            fields = lines[cursor].split("\t")
            if len(fields) < 5 or fields[:3] != ["terminator", f"{record.ordinal:02}", str(block_id)]:
                raise Elf64Error("candidate terminator row drifted")
            blocks.append(Block(block_id, tuple(operations), tuple(fields[3:])))
            cursor += 1
        encodings = []
        for _ in range(record.operation_count + record.terminator_count):
            fields = lines[cursor].split("\t")
            if len(fields) != 7 or fields[:2] != ["encoding", f"{record.ordinal:02}"]:
                raise Elf64Error("candidate encoding row drifted")
            encodings.append(Encoding(
                _uint(fields[2], "encoding block", 10_000),
                _uint(fields[3], "encoding ordinal", 10_000), fields[4],
                _uint(fields[5], "encoding start", MAX_TARGET_BYTES),
                _uint(fields[6], "encoding end", MAX_TARGET_BYTES),
            ))
            cursor += 1
        mappings = []
        for residual_ip in range(record.mapping_count):
            fields = lines[cursor].split("\t")
            if len(fields) != 6 or fields[:2] != ["correspondence", f"{record.ordinal:02}"]:
                raise Elf64Error("candidate correspondence row drifted")
            mappings.append(Mapping(
                _uint(fields[2], "residual ip", 10_000),
                _uint(fields[3], "mapping block", 10_000),
                _uint(fields[4], "mapping ordinal", 10_000), fields[5],
            ))
            if mappings[-1].residual_ip != residual_ip:
                raise Elf64Error("residual mapping identities are not contiguous")
            cursor += 1
        target_fields = lines[cursor].split("\t")
        elf_fields = lines[cursor + 1].split("\t")
        if target_fields[:2] != ["target-hex", f"{record.ordinal:02}"] or len(target_fields) != 3:
            raise Elf64Error("target hex row drifted")
        if elf_fields[:2] != ["elf-hex", f"{record.ordinal:02}"] or len(elf_fields) != 3:
            raise Elf64Error("ELF hex row drifted")
        try:
            target = bytes.fromhex(target_fields[2])
            elf = bytes.fromhex(elf_fields[2])
        except ValueError as error:
            raise Elf64Error("candidate contains non-hex target bytes") from error
        if target.hex() != target_fields[2] or elf.hex() != elf_fields[2]:
            raise Elf64Error("candidate hex is not canonical lowercase")
        cursor += 2
        kernel = Kernel(record, tuple(blocks), tuple(encodings), tuple(mappings), target, elf)
        _verify_kernel(kernel)
        kernels.append(kernel)
    if cursor != len(lines) - 1:
        raise Elf64Error("candidate has trailing or missing rows")
    return Candidate(tuple(kernels), raw)


def _report(contract: Contract, authority: Authority, candidate: Candidate | None) -> bytes:
    rows = [
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        "status\tx86-64-elf64-structurally-admitted",
        "execution-status\tforbidden",
        "claim-status\tnot-admitted",
        "timing-status\tforbidden",
        "kernels\t4",
        "blockers\t2",
        "blocker\tfresh-process-checksum-parity-unavailable",
        "blocker\tnaux-residual-role-admission-unavailable",
    ]
    if candidate is None:
        rows.extend(("mode\tstatic-authority", "replays\t0"))
    else:
        rows.extend((
            "mode\tuntimed-elf64-replay", "replays\t2",
            f"candidate\t{_sha256(candidate.raw)}",
            f"target-aggregate\t{_sha256(''.join(k.record.target_hash for k in candidate.kernels).encode())}",
            f"elf-aggregate\t{_sha256(''.join(k.record.elf_hash for k in candidate.kernels).encode())}",
        ))
    body = "".join(f"{row}\n" for row in rows).encode()
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode()


def validate(root: Path) -> Admission:
    parent = wp5c.validate(root)
    if parent.authority.seal != WP5C_AUTHORITY_SEAL:
        raise Elf64Error("WP5C parent authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP5D-ELF64.tsv")
    authority = parse_authority(root / "distribution/s4-performance/WP5D-AUTHORITY.tsv", contract.seal)
    _verify_files(root, authority)
    _verify_source_boundary(root)
    report = _report(contract, authority, None)
    return Admission(contract, authority, report, report.decode().split("report-root\t", 1)[1].strip())


def _run(binary: Path) -> subprocess.CompletedProcess[bytes]:
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C"}
    return subprocess.run(
        [os.fspath(binary)], input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment, check=False, timeout=30,
    )


def _looks_like_generated_wp5d_image(binary: Path) -> bool:
    """Reject every x86-64 ET_EXEC image before this gate can launch it.

    The reviewed Rust emitter is a host PIE (ET_DYN).  WP5D output is ET_EXEC,
    and policy must keep rejecting it even after an adversarial header mutation.
    """
    with binary.open("rb") as stream:
        header = stream.read(20)
    if len(header) < 20 or header[:7] != b"\x7fELF\x02\x01\x01":
        return False
    return struct.unpack_from("<H", header, 16)[0] == 2 and struct.unpack_from(
        "<H", header, 18
    )[0] == 62


def _validate_emitter_binary(binary: Path) -> None:
    if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise Elf64Error("reviewed WP5D emitter is not a regular executable")
    if binary.name != "naux_s4_residual_elf64":
        raise Elf64Error("reviewed WP5D emitter has a noncanonical filename")
    if _looks_like_generated_wp5d_image(binary):
        raise Elf64Error("refusing to execute a generated WP5D ELF64 image")


def replay(admission: Admission, binary: Path) -> tuple[bytes, Candidate]:
    _validate_emitter_binary(binary)
    reviewed_binary = binary.resolve(strict=True)
    first = _run(reviewed_binary)
    second = _run(reviewed_binary)
    for completed in (first, second):
        if completed.returncode != 0 or completed.stderr:
            raise Elf64Error("WP5D emitter did not exit cleanly and silently")
    if first.stdout != second.stdout:
        raise Elf64Error("WP5D emitter is nondeterministic")
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
            sys.stdout.buffer.write(admission.report)
        else:
            report, _ = replay(admission, arguments.binary)
            sys.stdout.buffer.write(report)
    except (Elf64Error, wp5c.MachineIrError, OSError, subprocess.TimeoutExpired) as error:
        print(f"S4-WP5D validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
