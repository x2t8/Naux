#!/usr/bin/env python3
"""Validate and independently replay the clock-free S4-WP5C Machine IR."""

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

import s4_structural_residual as wp5b


CONTRACT_MAGIC = "NAUX-S4-RESIDUAL-MACHINE-IR-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-RESIDUAL-MACHINE-IR-AUTHORITY\t1"
CANDIDATE_MAGIC = "NAUX-S4-RESIDUAL-MACHINE-IR\t1"
REPORT_MAGIC = "NAUX-S4-RESIDUAL-MACHINE-IR-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-residual-machine-ir:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-residual-machine-ir:authority:v1\0"
MACHINE_DOMAIN = b"NAUX:s4-residual-machine-ir:program:v1\0"
CORRESPONDENCE_DOMAIN = b"NAUX:s4-residual-machine-ir:correspondence:v1\0"
REPORT_DOMAIN = b"NAUX:s4-residual-machine-ir:report:v1\0"
WP5B_AUTHORITY_SEAL = "f41ed069566b2017aae0cce074df6f2b4d3aba3b1402e0bc50da285a62fb9cc7"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")
REGISTER_RE = re.compile(r"r(0|[1-9][0-9]*):(unit|bool|i64|owned-list-i64)\Z")
SLOT_RE = re.compile(r"s(0|[1-9][0-9]*)\Z")
BLOCK_RE = re.compile(r"b(0|[1-9][0-9]*)\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
MAX_CANDIDATE_BYTES = 512_000

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-authority", WP5B_AUTHORITY_SEAL),
    ("machine-status", "residual-machine-ir-admitted"),
    ("elf-status", "unavailable"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("target", "target-independent"),
    ("dataset", "static-n16384-r50"),
    ("input-ir", "closed-wp5b-v1"),
    ("machine-ir", "closed-wp5c-v1"),
    ("pipeline", "single-stack-to-typed-register-lowering"),
    ("kernel-count", "4"),
    ("correspondence", "exact-one-source-map-per-residual-op"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP5C"),
    ("authority-id", "s4-residual-machine-ir-v1"),
    ("machine-status", "residual-machine-ir-admitted"),
    ("elf-status", "unavailable"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("kernel-count", "4"),
    ("file-count", "8"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-residual-machine-ir.yml",
    "distribution/s4-performance/WP5C-NONCLAIMS.md",
    "distribution/s4-performance/WP5C-README.md",
    "distribution/s4-performance/WP5C-MACHINE-IR.tsv",
    "naux-lang/examples/naux_s4_residual_machine_ir.rs",
    "naux-lang/examples/support/s4_residual_machine_ir.rs",
    "scripts/s4_residual_machine_ir.py",
    "scripts/tests/test_s4_residual_machine_ir.py",
)
EXPECTED_KERNELS = (
    (
        "01", "sum-dense",
        "bed3ac1758cf4e32b195169bb5581e5bf05c74e2d65e3b04dcc704f7e9db17b3",
        "5594c78b156929f021990ba06ebc045d17316f2c45b432a1009f210f6b985cac",
        "97d8699e9449d53f4f3c9386839099be194b7db985709122092dfac3eacb8f2d",
        "398214c2c26688f24f117404e8255e176566fb9cc609051e0b74b0fe6f2aac8b",
        "7", "7", "43", "7", "29", "48", "0",
    ),
    (
        "02", "branch-mix",
        "7afa7cbefda8ec01364ba7ffde6ce36ec65fac5c00137d67da06059ca74e3508",
        "1f188884b4bb04d85dc00608cf436c6b07d8a665d17f63d7d8ab8192749ba195",
        "8095c962d36b2a6876770412feac0df8fdd5f4e3627481f97f6b78f9bc489888",
        "e899fb87be4673c99a42a9774401787c172f6601e55b67fd373880fcf271a1e2",
        "8", "12", "50", "12", "35", "58", "0",
    ),
    (
        "03", "dot-product",
        "6ef5fe036206185c65b1ff0abfbc51cb7b6f8541aec3a4bdfb967be2a7559353",
        "62291dc2f6662fdcb8f0a0e0d6f04a8a6f31ce498e6572a5908602b1ed7f2f7f",
        "b2fa698b60cb29e50d14e7f56650d1f09657562e3160e99bc7930e60f7c9e857",
        "fd5c9d8175926dff04b8d26e93e864e41b294fdfb40993a4f2db6f5b184e9416",
        "8", "7", "41", "7", "28", "46", "0",
    ),
    (
        "04", "list-update",
        "3a7cbf9174f6bdb8502cbe3ca7a88e71dc522e6ebfa007a4c588b1c7f12bb58f",
        "a7937fa3e64d75cf6a96165d0e63baa4a0dc66b365647af8a87b3ea07079dc55",
        "c6ac1a97cad0ec0529e7f5f49bb91d316fa63a2b9abb2c7452a0040fe4150199",
        "c8d1d121a36f74cbd6521be13a74b62e52899697cbc8faedb8a421c2de8193bd",
        "9", "7", "46", "7", "32", "51", "1",
    ),
)
COLUMNS = (
    "columns\tordinal\tkernel\tresidual-hash\twitness-hash\tmachine-hash\t"
    "correspondence-hash\tblock-count\tinstruction-count\tterminator-count\t"
    "register-count\tmapping-count\ttraversal-count\tlist-loads\tlist-stores"
)
FORBIDDEN_TIMING = (
    "instant::", "systemtime::", ".elapsed()", "duration_since(",
    "runtime_ns", "compile_ns", "runtime-ns", "compile-ns", "throughput", "latency", "median",
)


class MachineIrError(RuntimeError):
    """A fail-closed S4-WP5C validation error."""


@dataclass(frozen=True)
class ContractRecord:
    ordinal: int
    name: str
    residual_hash: str
    witness_hash: str
    machine_hash: str
    correspondence_hash: str
    slot_count: int
    block_count: int
    instruction_count: int
    terminator_count: int
    register_count: int
    mapping_count: int
    list_stores: int


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
    start: int
    end: int
    instructions: tuple[tuple[str, ...], ...]
    terminator: tuple[str, ...]


@dataclass(frozen=True)
class Mapping:
    residual_ip: int
    block: int
    machine_ordinal: int
    kind: str
    residual_op: tuple[str, ...]


@dataclass(frozen=True)
class Kernel:
    record: ContractRecord
    slots: tuple[str, ...]
    blocks: tuple[Block, ...]
    mappings: tuple[Mapping, ...]
    correspondence: tuple[int, ...]


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
        raise MachineIrError(f"{label} has invalid extent")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise MachineIrError(f"{label} is not UTF-8") from error
    if "\r" in text or "\x00" in text:
        raise MachineIrError(f"{label} is not canonical LF text")
    lines = text.splitlines()
    if any(not line for line in lines):
        raise MachineIrError(f"{label} contains a blank row")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    lines = _canonical(path.read_bytes(), path.as_posix())
    if len(lines) < 3 or lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise MachineIrError(f"unsupported sealed document: {path}")
    if any(line.startswith("seal\t") for line in lines[:-1]):
        raise MachineIrError(f"duplicated seal: {path}")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise MachineIrError(f"invalid terminal seal: {path}")
    body = "".join(f"{line}\n" for line in lines[:-1]).encode()
    if _sha256(domain + body) != fields[1]:
        raise MachineIrError(f"seal mismatch: {path}")
    return lines[1:-1], fields[1]


def _uint(value: str, label: str, maximum: int = (1 << 64) - 1) -> int:
    if not UINT_RE.fullmatch(value) or int(value) > maximum:
        raise MachineIrError(f"invalid unsigned integer in {label}")
    return int(value)


def _sint(value: str, label: str) -> int:
    if not INT_RE.fullmatch(value):
        raise MachineIrError(f"invalid signed integer in {label}")
    parsed = int(value)
    if parsed < -(1 << 63) or parsed >= 1 << 63:
        raise MachineIrError(f"signed integer exceeds i64 in {label}")
    return parsed


def _hash(value: str, label: str) -> str:
    if not HASH_RE.fullmatch(value):
        raise MachineIrError(f"invalid SHA-256 in {label}")
    return value


def _ordinal(value: str, label: str) -> int:
    if value not in ("01", "02", "03", "04"):
        raise MachineIrError(f"invalid two-digit ordinal in {label}")
    return int(value)


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if len(rows) != len(CONTRACT_METADATA) + 4:
        raise MachineIrError("unexpected WP5C contract extent")
    metadata = []
    for row in rows[: len(CONTRACT_METADATA)]:
        fields = row.split("\t")
        if len(fields) != 3 or fields[0] != "meta":
            raise MachineIrError("invalid WP5C contract metadata")
        metadata.append((fields[1], fields[2]))
    if tuple(metadata) != CONTRACT_METADATA:
        raise MachineIrError("WP5C contract metadata drifted")
    records = []
    for expected, row in zip(EXPECTED_KERNELS, rows[len(CONTRACT_METADATA) :]):
        fields = row.split("\t")
        if len(fields) != 14 or fields[0] != "kernel" or tuple(fields[1:]) != expected:
            raise MachineIrError("WP5C kernel identity drifted")
        records.append(
            ContractRecord(
                _ordinal(fields[1], "contract ordinal"), fields[2],
                _hash(fields[3], "residual hash"), _hash(fields[4], "witness hash"),
                _hash(fields[5], "machine hash"), _hash(fields[6], "correspondence hash"),
                *(_uint(value, "contract count", 10_000) for value in fields[7:14]),
            )
        )
    return Contract(tuple(records), seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    if len(rows) != len(AUTHORITY_METADATA) + 2 + len(EXPECTED_FILES):
        raise MachineIrError("unexpected WP5C authority extent")
    metadata = []
    for row in rows[: len(AUTHORITY_METADATA)]:
        fields = row.split("\t")
        if len(fields) != 3 or fields[0] != "meta":
            raise MachineIrError("invalid WP5C authority metadata")
        metadata.append((fields[1], fields[2]))
    if tuple(metadata) != AUTHORITY_METADATA:
        raise MachineIrError("WP5C authority metadata drifted")
    if rows[len(AUTHORITY_METADATA)].split("\t") != [
        "component", "residual-machine-ir-contract",
        "distribution/s4-performance/WP5C-MACHINE-IR.tsv", contract_seal,
    ]:
        raise MachineIrError("WP5C contract component drifted")
    if rows[len(AUTHORITY_METADATA) + 1].split("\t") != [
        "parent", "structural-residual-authority",
        "distribution/s4-performance/WP5B-AUTHORITY.tsv", WP5B_AUTHORITY_SEAL,
    ]:
        raise MachineIrError("WP5C parent authority drifted")
    files = []
    for expected, row in zip(EXPECTED_FILES, rows[len(AUTHORITY_METADATA) + 2 :]):
        fields = row.split("\t")
        if len(fields) != 5 or fields[0] != "file" or fields[4] != expected:
            raise MachineIrError("WP5C file inventory drifted")
        if not MODE_RE.fullmatch(fields[1]) or not PATH_RE.fullmatch(fields[4]):
            raise MachineIrError("invalid WP5C authority file row")
        files.append(FileRecord(int(fields[1], 8), _uint(fields[2], "file size"), _hash(fields[3], "file hash"), fields[4]))
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    if tuple(record.path for record in authority.files) != EXPECTED_FILES:
        raise MachineIrError("WP5C authority does not bind the exact file set")
    for record in authority.files:
        path = root / record.path
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            raise MachineIrError(f"WP5C file is not regular: {record.path}")
        raw = path.read_bytes()
        mode = stat.S_IFREG | stat.S_IMODE(info.st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise MachineIrError(f"WP5C file drifted: {record.path}")


def _verify_source_boundary(root: Path) -> None:
    generic = (root / "naux-lang/examples/support/s4_residual_machine_ir.rs").read_text().lower()
    for name in ("sum-dense", "branch-mix", "dot-product", "list-update"):
        if name in generic:
            raise MachineIrError("generic Machine IR lowering dispatches on a kernel identity")
    combined = b"".join((root / path).read_bytes().lower() for path in (
        "naux-lang/examples/naux_s4_residual_machine_ir.rs",
        "naux-lang/examples/support/s4_residual_machine_ir.rs",
    ))
    for token in FORBIDDEN_TIMING:
        if token.encode() in combined:
            raise MachineIrError(f"WP5C source contains forbidden timing token: {token}")


def _put_u32(buffer: bytearray, value: int) -> None:
    buffer.extend(struct.pack("<I", value))


def _put_u64(buffer: bytearray, value: int) -> None:
    buffer.extend(struct.pack("<Q", value))


def _put_string(buffer: bytearray, value: str) -> None:
    encoded = value.encode()
    _put_u32(buffer, len(encoded))
    buffer.extend(encoded)


def _machine_hash(kernel: Kernel) -> str:
    record = kernel.record
    payload = bytearray.fromhex(record.residual_hash)
    payload.extend(bytes.fromhex(record.witness_hash))
    _put_u32(payload, 0)
    _put_u32(payload, record.register_count)
    _put_u32(payload, len(kernel.slots))
    for slot_type in kernel.slots:
        _put_string(payload, slot_type)
    _put_u32(payload, len(kernel.blocks))
    for block in kernel.blocks:
        _put_u32(payload, block.block_id)
        _put_u32(payload, block.start)
        _put_u32(payload, block.end)
        _put_u32(payload, len(block.instructions))
        for instruction in block.instructions:
            _put_string(payload, "\t".join(instruction))
        _put_string(payload, "\t".join(block.terminator))
    _put_u32(payload, len(kernel.mappings))
    for mapping in kernel.mappings:
        _put_u32(payload, mapping.residual_ip)
        _put_u32(payload, mapping.block)
        _put_u32(payload, mapping.machine_ordinal)
        _put_string(payload, mapping.kind)
    return _sha256(MACHINE_DOMAIN + payload)


def _correspondence_hash(kernel: Kernel) -> str:
    values = kernel.correspondence
    payload = bytearray.fromhex(kernel.record.machine_hash)
    payload.extend(bytes.fromhex(kernel.record.residual_hash))
    payload.extend(bytes.fromhex(kernel.record.witness_hash))
    for value in (*values[:11], values[12], values[13]):
        _put_u32(payload, value)
    _put_u64(payload, values[11])
    return _sha256(CORRESPONDENCE_DOMAIN + payload)


def _register(value: str, label: str) -> tuple[int, str]:
    match = REGISTER_RE.fullmatch(value)
    if match is None:
        raise MachineIrError(f"invalid typed register in {label}")
    return _uint(match.group(1), label, 100_000), match.group(2)


def _slot(value: str, label: str) -> int:
    match = SLOT_RE.fullmatch(value)
    if match is None:
        raise MachineIrError(f"invalid slot in {label}")
    return _uint(match.group(1), label, 10_000)


def _block(value: str, label: str) -> int:
    match = BLOCK_RE.fullmatch(value)
    if match is None:
        raise MachineIrError(f"invalid block in {label}")
    return _uint(match.group(1), label, 10_000)


def _instruction_signature(fields: tuple[str, ...], slots: tuple[str, ...]) -> tuple[tuple[int, str] | None, tuple[tuple[int, str], ...]]:
    op = fields[0]
    producers = {"const-i64", "load-slot", "range-allocate-init", "list-length-static", "list-load-checked", "list-store-checked"}
    if op.startswith("i64-"):
        producers.add(op)
    result = _register(fields[1], op) if op in producers else None
    uses: list[tuple[int, str]] = []
    if op == "const-i64":
        if len(fields) != 3 or result is None or result[1] != "i64":
            raise MachineIrError("invalid const-i64 shape")
        _sint(fields[2], op)
    elif op == "load-slot":
        if len(fields) != 3:
            raise MachineIrError("invalid load-slot shape")
        slot = _slot(fields[2], op)
        if slot >= len(slots) or result is None or slots[slot] != result[1]:
            raise MachineIrError("load-slot type disagrees with frame")
    elif op == "store-slot":
        if len(fields) != 4 or fields[3] not in ("keep", "consume"):
            raise MachineIrError("invalid store-slot shape")
        slot = _slot(fields[1], op)
        value = _register(fields[2], op)
        if slot >= len(slots) or slots[slot] != value[1]:
            raise MachineIrError("store-slot type disagrees with frame")
        uses.append(value)
    elif op == "add-slot-const":
        if len(fields) != 3:
            raise MachineIrError("invalid add-slot-const shape")
        slot = _slot(fields[1], op)
        _sint(fields[2], op)
        if slot >= len(slots) or slots[slot] != "i64":
            raise MachineIrError("add-slot-const targets non-i64 slot")
    elif op in {"i64-add", "i64-sub", "i64-mul", "i64-div", "i64-mod", "i64-xor", "i64-shl", "i64-and", "i64-or"}:
        if len(fields) != 4 or result is None or result[1] != "i64":
            raise MachineIrError("invalid i64 binary shape")
        uses.extend((_register(fields[2], op), _register(fields[3], op)))
        if any(ty != "i64" for _, ty in uses):
            raise MachineIrError("i64 binary consumes non-i64 register")
    elif op in {"i64-eq", "i64-ne", "i64-gt", "i64-ge", "i64-lt", "i64-le"}:
        if len(fields) != 4 or result is None or result[1] != "bool":
            raise MachineIrError("invalid i64 compare shape")
        uses.extend((_register(fields[2], op), _register(fields[3], op)))
        if any(ty != "i64" for _, ty in uses):
            raise MachineIrError("i64 compare consumes non-i64 register")
    elif op == "range-allocate-init":
        if len(fields) != 3 or result is None or result[1] != "owned-list-i64" or _uint(fields[2], op) != 16_384:
            raise MachineIrError("invalid range allocation shape")
    elif op == "list-length-static":
        if len(fields) != 4 or result is None or result[1] != "i64" or _uint(fields[3], op) != 16_384:
            raise MachineIrError("invalid static list length shape")
        slot = _slot(fields[2], op)
        if slot >= len(slots) or slots[slot] != "owned-list-i64":
            raise MachineIrError("static list length targets non-list slot")
    elif op == "list-load-checked":
        if len(fields) != 4 or result is None or result[1] != "i64":
            raise MachineIrError("invalid checked list load shape")
        uses.extend((_register(fields[2], op), _register(fields[3], op)))
        if tuple(ty for _, ty in uses) != ("owned-list-i64", "i64"):
            raise MachineIrError("checked list load operand types drifted")
    elif op == "list-store-checked":
        if len(fields) != 5 or result is None or result[1] != "unit":
            raise MachineIrError("invalid checked list store shape")
        uses.extend((_register(fields[2], op), _register(fields[3], op), _register(fields[4], op)))
        if tuple(ty for _, ty in uses) != ("owned-list-i64", "i64", "i64"):
            raise MachineIrError("checked list store operand types drifted")
    elif op == "release-owned-list":
        if len(fields) != 2:
            raise MachineIrError("invalid owned-list release shape")
        slot = _slot(fields[1], op)
        if slot >= len(slots) or slots[slot] != "owned-list-i64":
            raise MachineIrError("owned-list release targets non-list slot")
    else:
        raise MachineIrError(f"unsupported Machine IR instruction: {op}")
    return result, tuple(uses)


def _verify_machine(kernel: Kernel) -> None:
    record = kernel.record
    if len(kernel.slots) != record.slot_count or kernel.slots.count("owned-list-i64") != 1:
        raise MachineIrError("closed slot frame drifted")
    if any(slot not in ("unit", "bool", "i64", "owned-list-i64") for slot in kernel.slots):
        raise MachineIrError("unsupported closed slot type")
    if len(kernel.blocks) != record.block_count or len(kernel.mappings) != record.mapping_count:
        raise MachineIrError("machine extent disagrees with contract")
    expected_start = 0
    definitions: dict[int, str] = {}
    allocation_sites: list[int] = []
    release_sites: list[int] = []
    list_load_blocks: list[int] = []
    list_store_blocks: list[int] = []
    edges: dict[int, set[int]] = {}
    instruction_count = 0
    for expected_id, block in enumerate(kernel.blocks):
        if block.block_id != expected_id or block.start != expected_start or block.start >= block.end:
            raise MachineIrError("machine block ranges are not canonical and contiguous")
        expected_start = block.end
        instruction_count += len(block.instructions)
        for ordinal, instruction in enumerate(block.instructions):
            result, uses = _instruction_signature(instruction, kernel.slots)
            for register, ty in uses:
                if definitions.get(register) != ty:
                    raise MachineIrError("Machine IR register use precedes an equal typed definition")
            if result is not None:
                register, ty = result
                if register in definitions:
                    raise MachineIrError("Machine IR register is defined more than once")
                definitions[register] = ty
            if instruction[0] == "range-allocate-init":
                allocation_sites.append(block.block_id)
            elif instruction[0] == "release-owned-list":
                release_sites.append(block.block_id)
            elif instruction[0] == "list-load-checked":
                list_load_blocks.append(block.block_id)
            elif instruction[0] == "list-store-checked":
                list_store_blocks.append(block.block_id)
        term = block.terminator
        if term[0] == "goto" and len(term) == 2:
            targets = {_block(term[1], "goto")}
        elif term[0] == "branch" and len(term) == 4:
            condition = _register(term[1], "branch")
            if condition[1] != "bool" or definitions.get(condition[0]) != "bool":
                raise MachineIrError("branch condition is not a defined bool")
            targets = {_block(term[2], "branch"), _block(term[3], "branch")}
        elif term[0] == "return" and len(term) == 2:
            value = _register(term[1], "return")
            if value[1] != "i64" or definitions.get(value[0]) != "i64":
                raise MachineIrError("return value is not a defined i64")
            targets = set()
        else:
            raise MachineIrError("unsupported Machine IR terminator")
        if any(target >= len(kernel.blocks) for target in targets):
            raise MachineIrError("Machine IR terminator targets missing block")
        edges[block.block_id] = targets
    if expected_start != record.mapping_count or instruction_count != record.instruction_count:
        raise MachineIrError("machine blocks do not cover the residual extent")
    if sorted(definitions) != list(range(record.register_count)):
        raise MachineIrError("virtual register identities are not contiguous SSA definitions")
    reachable = {0}
    frontier = [0]
    while frontier:
        block = frontier.pop()
        for successor in edges[block]:
            if successor not in reachable:
                reachable.add(successor)
                frontier.append(successor)
    if reachable != set(range(len(kernel.blocks))):
        raise MachineIrError("Machine IR contains an unreachable block")
    if len(allocation_sites) != 1 or len(release_sites) != 1:
        raise MachineIrError("Machine IR does not retain exact allocation and release")
    if len(list_load_blocks) != 1 or len(list_store_blocks) != record.list_stores:
        raise MachineIrError("Machine IR list-effect count drifted")
    backedges = sorted((source, target) for source, targets in edges.items() for target in targets if target <= source)
    if len(backedges) != 2:
        raise MachineIrError("Machine IR does not retain exactly two loop backedges")
    values = kernel.correspondence
    if values[0:5] != (record.block_count, record.instruction_count, record.terminator_count, record.register_count, record.mapping_count):
        raise MachineIrError("correspondence extent disagrees with contract")
    allocation, release, outer_header, outer_exit, inner_header, inner_exit = values[5:11]
    if allocation != allocation_sites[0] or release != release_sites[0]:
        raise MachineIrError("correspondence ownership sites drifted")
    if sorted(target for _, target in backedges) != sorted((outer_header, inner_header)):
        raise MachineIrError("correspondence loop headers drifted")
    outer_term = kernel.blocks[outer_header].terminator
    inner_term = kernel.blocks[inner_header].terminator
    if outer_term[0] != "branch" or _block(outer_term[3], "outer exit") != outer_exit:
        raise MachineIrError("outer loop exit correspondence drifted")
    if inner_term[0] != "branch" or _block(inner_term[3], "inner exit") != inner_exit:
        raise MachineIrError("inner loop exit correspondence drifted")
    if release != outer_exit or values[11:] != (819_200, 1, record.list_stores):
        raise MachineIrError("machine work witness drifted")
    if _machine_hash(kernel) != record.machine_hash or _correspondence_hash(kernel) != record.correspondence_hash:
        raise MachineIrError("machine or correspondence identity mismatch")


def _verify_mapping(kernel: Kernel) -> None:
    record = kernel.record
    if tuple(mapping.residual_ip for mapping in kernel.mappings) != tuple(range(record.mapping_count)):
        raise MachineIrError("source map is not exact residual order")
    map_by_ip = {mapping.residual_ip: mapping for mapping in kernel.mappings}
    stack: list[tuple[int, str]] = []

    def stack_pop(label: str) -> tuple[int, str]:
        if not stack:
            raise MachineIrError(f"residual stack underflow in {label} correspondence")
        return stack.pop()

    previous_block = 0
    for mapping in kernel.mappings:
        if mapping.block >= len(kernel.blocks):
            raise MachineIrError("source map names a missing block")
        block = kernel.blocks[mapping.block]
        if not (block.start <= mapping.residual_ip < block.end):
            raise MachineIrError("source map escaped its machine block range")
        if mapping.block != previous_block:
            if stack:
                raise MachineIrError("source stack crosses a Machine IR block edge")
            previous_block = mapping.block
        if mapping.kind == "instruction" and mapping.machine_ordinal >= len(block.instructions):
            raise MachineIrError("instruction mapping ordinal is out of range")
        if mapping.kind == "terminator" and mapping.machine_ordinal != len(block.instructions):
            raise MachineIrError("terminator mapping ordinal drifted")
        residual = mapping.residual_op
        machine = block.terminator if mapping.kind == "terminator" else block.instructions[mapping.machine_ordinal]
        op = residual[0]
        if op == "const-i64":
            if machine[0] != "const-i64" or machine[2:] != residual[1:]:
                raise MachineIrError("constant correspondence drifted")
            stack.append(_register(machine[1], op))
        elif op == "load-local":
            if machine[0] != "load-slot" or _slot(machine[2], op) != _uint(residual[1], op):
                raise MachineIrError("local load correspondence drifted")
            stack.append(_register(machine[1], op))
        elif op in ("store-local", "store-local-keep"):
            value = stack_pop(op)
            keep = op == "store-local-keep"
            if machine != ("store-slot", f"s{residual[1]}", f"r{value[0]}:{value[1]}", "keep" if keep else "consume"):
                raise MachineIrError("local store correspondence drifted")
            if keep:
                stack.append(value)
        elif op == "add-local-const":
            if machine != ("add-slot-const", f"s{residual[1]}", residual[2]):
                raise MachineIrError("local increment correspondence drifted")
        elif op in ("add", "sub", "mul", "div", "mod", "xor", "shl", "and", "or", "eq", "ne", "gt", "ge", "lt", "le"):
            right = stack_pop(op)
            left = stack_pop(op)
            if machine[0] != f"i64-{op}" or _register(machine[2], op) != left or _register(machine[3], op) != right:
                raise MachineIrError("binary correspondence drifted")
            stack.append(_register(machine[1], op))
        elif op == "range-allocate-init":
            if machine[0] != op or machine[2] != residual[1]:
                raise MachineIrError("allocation correspondence drifted")
            stack.append(_register(machine[1], op))
        elif op == "list-length-static":
            if machine[0] != op or machine[2:] != (f"s{residual[1]}", residual[2]):
                raise MachineIrError("list length correspondence drifted")
            stack.append(_register(machine[1], op))
        elif op == "list-load":
            index = stack_pop(op)
            owner = stack_pop(op)
            if machine[0] != "list-load-checked" or _register(machine[2], op) != owner or _register(machine[3], op) != index:
                raise MachineIrError("list load correspondence drifted")
            stack.append(_register(machine[1], op))
        elif op == "list-store":
            value, index, owner = stack_pop(op), stack_pop(op), stack_pop(op)
            if machine[0] != "list-store-checked" or tuple(_register(item, op) for item in machine[2:]) != (owner, index, value):
                raise MachineIrError("list store correspondence drifted")
            stack.append(_register(machine[1], op))
        elif op == "release-list":
            if machine != ("release-owned-list", f"s{residual[1]}"):
                raise MachineIrError("release correspondence drifted")
        elif op == "jump":
            target = map_by_ip[_uint(residual[1], op)].block
            if machine != ("goto", f"b{target}"):
                raise MachineIrError("jump correspondence drifted")
        elif op == "jump-if-false":
            condition = stack_pop(op)
            false_target = map_by_ip[_uint(residual[1], op)].block
            true_target = map_by_ip[mapping.residual_ip + 1].block
            if machine != ("branch", f"r{condition[0]}:{condition[1]}", f"b{true_target}", f"b{false_target}"):
                raise MachineIrError("conditional correspondence drifted")
        elif op == "return":
            value = stack_pop(op)
            if machine != ("return", f"r{value[0]}:{value[1]}"):
                raise MachineIrError("return correspondence drifted")
        else:
            raise MachineIrError(f"unsupported residual mapping opcode: {op}")
        if mapping.residual_ip + 1 == block.end and stack:
            raise MachineIrError("source stack is nonempty at Machine IR block exit")
    if stack:
        raise MachineIrError("source stack remains after final mapping")


def parse_candidate(raw: bytes, contract: Contract) -> Candidate:
    lines = _canonical(raw, "WP5C candidate", MAX_CANDIDATE_BYTES)
    prefix = [
        CANDIDATE_MAGIC,
        "meta\tstatus\tresidual-machine-ir-admitted",
        "meta\telf-status\tunavailable",
        "meta\ttiming-status\tforbidden",
        COLUMNS,
    ]
    if lines[:5] != prefix or lines[-1] != "verification\tregenerated":
        raise MachineIrError("WP5C candidate header or terminal marker drifted")
    cursor = 5
    kernels = []
    for record in contract.records:
        fields = lines[cursor].split("\t")
        cursor += 1
        expected = (
            "kernel", f"{record.ordinal:02}", record.name, record.residual_hash,
            record.witness_hash, record.machine_hash, record.correspondence_hash,
            str(record.block_count), str(record.instruction_count), str(record.terminator_count),
            str(record.register_count), str(record.mapping_count), "819200", "1", str(record.list_stores),
        )
        if tuple(fields) != expected:
            raise MachineIrError("WP5C candidate kernel row drifted")
        slots = []
        for slot in range(record.slot_count):
            fields = lines[cursor].split("\t")
            cursor += 1
            if len(fields) != 4 or fields[:3] != ["slot", f"{record.ordinal:02}", str(slot)]:
                raise MachineIrError("WP5C slot row drifted")
            slots.append(fields[3])
        blocks = []
        for block_id in range(record.block_count):
            fields = lines[cursor].split("\t")
            cursor += 1
            if len(fields) != 6 or fields[:3] != ["block", f"{record.ordinal:02}", str(block_id)]:
                raise MachineIrError("WP5C block row drifted")
            start, end, count = (_uint(value, "block row", 10_000) for value in fields[3:])
            instructions = []
            for instruction in range(count):
                fields = lines[cursor].split("\t")
                cursor += 1
                if len(fields) < 5 or fields[:4] != ["instruction", f"{record.ordinal:02}", str(block_id), str(instruction)]:
                    raise MachineIrError("WP5C instruction row drifted")
                instructions.append(tuple(fields[4:]))
            fields = lines[cursor].split("\t")
            cursor += 1
            if len(fields) < 4 or fields[:3] != ["terminator", f"{record.ordinal:02}", str(block_id)]:
                raise MachineIrError("WP5C terminator row drifted")
            blocks.append(Block(block_id, start, end, tuple(instructions), tuple(fields[3:])))
        mappings = []
        for residual_ip in range(record.mapping_count):
            fields = lines[cursor].split("\t")
            cursor += 1
            if len(fields) < 7 or fields[:3] != ["mapping", f"{record.ordinal:02}", str(residual_ip)] or fields[5] not in ("instruction", "terminator"):
                raise MachineIrError("WP5C mapping row drifted")
            mappings.append(Mapping(residual_ip, _uint(fields[3], "mapping block", 10_000), _uint(fields[4], "mapping ordinal", 10_000), fields[5], tuple(fields[6:])))
        fields = lines[cursor].split("\t")
        cursor += 1
        if len(fields) != 19 or fields[:5] != [
            "correspondence", f"{record.ordinal:02}", record.machine_hash,
            record.residual_hash, record.witness_hash,
        ]:
            raise MachineIrError("WP5C correspondence row drifted")
        values = tuple(_uint(value, "correspondence value", 10_000_000) for value in fields[5:])
        kernel = Kernel(record, tuple(slots), tuple(blocks), tuple(mappings), values)
        _verify_machine(kernel)
        _verify_mapping(kernel)
        kernels.append(kernel)
    if cursor != len(lines) - 1:
        raise MachineIrError("WP5C candidate has trailing or missing rows")
    return Candidate(tuple(kernels), raw)


def _report(contract: Contract, authority: Authority, candidate: Candidate | None) -> bytes:
    rows = [
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        "machine-status\tresidual-machine-ir-admitted",
        "elf-status\tunavailable",
        "claim-status\tnot-admitted",
        "timing-status\tforbidden",
        "kernels\t4",
        "blockers\t3",
        "blocker\telf-lowering-unavailable",
        "blocker\tfresh-process-parity-unavailable",
        "blocker\tnaux-residual-role-admission-unavailable",
    ]
    if candidate is None:
        rows.extend(("mode\tstatic-authority", "replays\t0"))
    else:
        rows.extend((
            "mode\tuntimed-machine-replay", "replays\t2",
            f"candidate\t{_sha256(candidate.raw)}",
            f"machine-aggregate\t{_sha256(''.join(kernel.record.machine_hash for kernel in candidate.kernels).encode())}",
            f"correspondence-aggregate\t{_sha256(''.join(kernel.record.correspondence_hash for kernel in candidate.kernels).encode())}",
        ))
    body = "".join(f"{row}\n" for row in rows).encode()
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode()


def validate(root: Path) -> Admission:
    parent = wp5b.validate(root)
    if parent.authority.seal != WP5B_AUTHORITY_SEAL:
        raise MachineIrError("WP5B parent authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP5C-MACHINE-IR.tsv")
    authority = parse_authority(root / "distribution/s4-performance/WP5C-AUTHORITY.tsv", contract.seal)
    _verify_files(root, authority)
    _verify_source_boundary(root)
    report = _report(contract, authority, None)
    return Admission(contract, authority, report, report.decode().split("report-root\t", 1)[1].strip())


def _run(binary: Path) -> subprocess.CompletedProcess[bytes]:
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "LANG": "C"}
    return subprocess.run([str(binary)], input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, check=False)


def replay(root: Path, admission: Admission, binary: Path) -> tuple[bytes, Candidate]:
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise MachineIrError("reviewed WP5C binary is not executable")
    first = _run(binary)
    second = _run(binary)
    for completed in (first, second):
        if completed.returncode != 0 or completed.stderr:
            raise MachineIrError("WP5C emitter did not exit cleanly and silently")
    if first.stdout != second.stdout:
        raise MachineIrError("WP5C emitter is nondeterministic")
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
            report, _ = replay(arguments.root.resolve(), admission, arguments.binary.resolve())
            sys.stdout.buffer.write(report)
    except (MachineIrError, wp5b.ResidualError, OSError) as error:
        print(f"S4-WP5C validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
