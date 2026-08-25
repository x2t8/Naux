#!/usr/bin/env python3
"""Validate and independently replay the clock-free S4-WP5B residual slice."""

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

import s4_specialization_request as wp5a


CONTRACT_MAGIC = "NAUX-S4-STRUCTURAL-RESIDUAL-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-STRUCTURAL-RESIDUAL-AUTHORITY\t1"
CANDIDATE_MAGIC = "NAUX-S4-STRUCTURAL-RESIDUAL\t1"
REPORT_MAGIC = "NAUX-S4-STRUCTURAL-RESIDUAL-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-structural-residual:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-structural-residual:authority:v1\0"
RESIDUAL_DOMAIN = b"NAUX:s4-whole-program-residual:program:v1\0"
WITNESS_DOMAIN = b"NAUX:s4-whole-program-residual:witness:v1\0"
REPORT_DOMAIN = b"NAUX:s4-structural-residual:report:v1\0"
WP5A_AUTHORITY_SEAL = "e86fa78b86865b389493a6f8cf4abae5acd8403c6413ec14d04ecb61eeef8d9e"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
MAX_CANDIDATE_BYTES = 65_536

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-authority", WP5A_AUTHORITY_SEAL),
    ("residual-status", "structural-residual-admitted"),
    ("native-status", "unavailable"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("dataset", "static-n16384-r50"),
    ("frontend", "ordinary-naux-frontend"),
    ("residual-ir", "closed-wp5b-v1"),
    ("pipeline", "single-general-whole-program-lowering"),
    ("kernel-count", "4"),
    ("work-obligations", "allocation-initialization-nested-traversal-checksum-teardown"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP5B"),
    ("authority-id", "s4-structural-residual-v1"),
    ("residual-status", "structural-residual-admitted"),
    ("native-status", "unavailable"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("kernel-count", "4"),
    ("file-count", "8"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-structural-residual.yml",
    "distribution/s4-performance/WP5B-NONCLAIMS.md",
    "distribution/s4-performance/WP5B-README.md",
    "distribution/s4-performance/WP5B-RESIDUAL.tsv",
    "naux-lang/examples/naux_s4_structural_residual.rs",
    "naux-lang/examples/support/s4_whole_program_residual.rs",
    "scripts/s4_structural_residual.py",
    "scripts/tests/test_s4_structural_residual.py",
)
EXPECTED_KERNELS = (
    (
        "01", "sum-dense", "benchmarks/s4/naux/sum_dense.nx",
        "0d9fdbcfacc75240b5d9ee9cbe129005ecb0e650d37c33f97a336a0209a0f97e",
        "e759edeb954fe8e49d2592daadb7756c9594ccbf05968c413dcbc3503ddfc95f",
        "bed3ac1758cf4e32b195169bb5581e5bf05c74e2d65e3b04dcc704f7e9db17b3",
        "5594c78b156929f021990ba06ebc045d17316f2c45b432a1009f210f6b985cac",
        "48", "0",
    ),
    (
        "02", "branch-mix", "benchmarks/s4/naux/branch_mix.nx",
        "aec8218746982d009a8049a1a929a618edb9db4be81e9b97a1c972b223ba55f5",
        "87753a3ea05f27dc7179132a74c5fecbdc41b486e36d32842e71b6a71ddfc483",
        "7afa7cbefda8ec01364ba7ffde6ce36ec65fac5c00137d67da06059ca74e3508",
        "1f188884b4bb04d85dc00608cf436c6b07d8a665d17f63d7d8ab8192749ba195",
        "58", "0",
    ),
    (
        "03", "dot-product", "benchmarks/s4/naux/dot_product.nx",
        "2fe19612a33bb27472dd10b2da705b313b1d59caa8eade48d4e18758c208ec20",
        "95c00feedbe8bba2107d7d8f5f61cb90c467a2e791cf54d36ea11c997e75bba6",
        "6ef5fe036206185c65b1ff0abfbc51cb7b6f8541aec3a4bdfb967be2a7559353",
        "62291dc2f6662fdcb8f0a0e0d6f04a8a6f31ce498e6572a5908602b1ed7f2f7f",
        "46", "0",
    ),
    (
        "04", "list-update", "benchmarks/s4/naux/list_update.nx",
        "20e549bbb4e28c566440e6981d120bc0839c4574c5abc374f99efcee4f576e90",
        "afd8290e10fb6ba90c3474764615e8be4a2968115cbe31e8543fec1307a98e93",
        "3a7cbf9174f6bdb8502cbe3ca7a88e71dc522e6ebfa007a4c588b1c7f12bb58f",
        "a7937fa3e64d75cf6a96165d0e63baa4a0dc66b365647af8a87b3ea07079dc55",
        "51", "1",
    ),
)
COLUMNS = (
    "columns\tordinal\tkernel\tresidual-hash\twitness-hash\tlocal-count\t"
    "n-local\treps-local\tlist-local\tchecksum-local\tn\treps\top-count\t"
    "traversal-count\tlist-loads\tlist-stores"
)
FORBIDDEN_TIMING = (
    "instant::", "systemtime::", ".elapsed()", "duration_since(",
    "runtime_ns", "compile_ns", "runtime-ns", "compile-ns", "throughput", "latency", "median",
)


class ResidualError(RuntimeError):
    """A fail-closed S4-WP5B validation error."""


@dataclass(frozen=True)
class ContractRecord:
    ordinal: int
    name: str
    source_path: str
    program_hash: str
    request_hash: str
    residual_hash: str
    witness_hash: str
    op_count: int
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
class Kernel:
    ordinal: int
    name: str
    residual_hash: str
    witness_hash: str
    local_count: int
    n_local: int
    reps_local: int
    list_local: int
    checksum_local: int
    n: int
    reps: int
    ops: tuple[tuple[str, ...], ...]
    witness: tuple[int, ...]


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
        raise ResidualError(f"{label} has invalid extent")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ResidualError(f"{label} is not UTF-8") from error
    if "\r" in text or "\x00" in text:
        raise ResidualError(f"{label} is not canonical LF text")
    lines = text.splitlines()
    if any(not line for line in lines):
        raise ResidualError(f"{label} contains a blank row")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    raw = path.read_bytes()
    lines = _canonical(raw, path.as_posix())
    if len(lines) < 3 or lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise ResidualError(f"unsupported sealed document: {path}")
    if any(line.startswith("seal\t") for line in lines[:-1]):
        raise ResidualError(f"duplicated seal: {path}")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise ResidualError(f"invalid terminal seal: {path}")
    body = "".join(f"{line}\n" for line in lines[:-1]).encode()
    if _sha256(domain + body) != fields[1]:
        raise ResidualError(f"seal mismatch: {path}")
    return lines[1:-1], fields[1]


def _uint(value: str, label: str, maximum: int = (1 << 64) - 1) -> int:
    if not UINT_RE.fullmatch(value) or int(value) > maximum:
        raise ResidualError(f"invalid unsigned integer in {label}")
    return int(value)


def _sint(value: str, label: str) -> int:
    if not INT_RE.fullmatch(value):
        raise ResidualError(f"invalid signed integer in {label}")
    parsed = int(value)
    if parsed < -(1 << 63) or parsed >= 1 << 63:
        raise ResidualError(f"signed integer exceeds i64 in {label}")
    return parsed


def _hash(value: str, label: str) -> str:
    if not HASH_RE.fullmatch(value):
        raise ResidualError(f"invalid SHA-256 in {label}")
    return value


def _ordinal(value: str, label: str) -> int:
    if value not in ("01", "02", "03", "04"):
        raise ResidualError(f"invalid two-digit ordinal in {label}")
    return int(value)


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if len(rows) != len(CONTRACT_METADATA) + 4:
        raise ResidualError("unexpected structural-residual contract extent")
    metadata = []
    for row in rows[: len(CONTRACT_METADATA)]:
        fields = row.split("\t")
        if len(fields) != 3 or fields[0] != "meta":
            raise ResidualError("invalid structural-residual metadata")
        metadata.append((fields[1], fields[2]))
    if tuple(metadata) != CONTRACT_METADATA:
        raise ResidualError("structural-residual metadata drifted")
    records = []
    for expected, row in zip(EXPECTED_KERNELS, rows[len(CONTRACT_METADATA) :]):
        fields = row.split("\t")
        if len(fields) != 10 or fields[0] != "kernel" or tuple(fields[1:]) != expected:
            raise ResidualError("structural-residual kernel identity drifted")
        records.append(
            ContractRecord(
                ordinal=_ordinal(fields[1], "contract ordinal"),
                name=fields[2],
                source_path=fields[3],
                program_hash=_hash(fields[4], "program hash"),
                request_hash=_hash(fields[5], "request hash"),
                residual_hash=_hash(fields[6], "residual hash"),
                witness_hash=_hash(fields[7], "witness hash"),
                op_count=_uint(fields[8], "op count", 10_000),
                list_stores=_uint(fields[9], "list stores", 10_000),
            )
        )
    return Contract(tuple(records), seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    if len(rows) != len(AUTHORITY_METADATA) + 2 + len(EXPECTED_FILES):
        raise ResidualError("unexpected WP5B authority extent")
    metadata = []
    for row in rows[: len(AUTHORITY_METADATA)]:
        fields = row.split("\t")
        if len(fields) != 3 or fields[0] != "meta":
            raise ResidualError("invalid WP5B authority metadata")
        metadata.append((fields[1], fields[2]))
    if tuple(metadata) != AUTHORITY_METADATA:
        raise ResidualError("WP5B authority metadata drifted")
    component = rows[len(AUTHORITY_METADATA)].split("\t")
    if component != [
        "component", "structural-residual-contract",
        "distribution/s4-performance/WP5B-RESIDUAL.tsv", contract_seal,
    ]:
        raise ResidualError("WP5B contract component drifted")
    parent = rows[len(AUTHORITY_METADATA) + 1].split("\t")
    if parent != [
        "parent", "specialization-request-authority",
        "distribution/s4-performance/WP5A-AUTHORITY.tsv", WP5A_AUTHORITY_SEAL,
    ]:
        raise ResidualError("WP5B parent authority drifted")
    files = []
    for expected, row in zip(EXPECTED_FILES, rows[len(AUTHORITY_METADATA) + 2 :]):
        fields = row.split("\t")
        if len(fields) != 5 or fields[0] != "file" or fields[4] != expected:
            raise ResidualError("WP5B file inventory drifted")
        if not MODE_RE.fullmatch(fields[1]) or not PATH_RE.fullmatch(fields[4]):
            raise ResidualError("invalid WP5B file row")
        files.append(FileRecord(int(fields[1], 8), _uint(fields[2], "file size"), _hash(fields[3], "file hash"), fields[4]))
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    if tuple(record.path for record in authority.files) != EXPECTED_FILES:
        raise ResidualError("WP5B authority does not bind the exact file set")
    for record in authority.files:
        path = root / record.path
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink():
            raise ResidualError(f"WP5B file is not a regular file: {record.path}")
        raw = path.read_bytes()
        mode = stat.S_IFREG | stat.S_IMODE(info.st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise ResidualError(f"WP5B file drifted: {record.path}")


def _verify_source_boundary(root: Path) -> None:
    support = (root / "naux-lang/examples/support/s4_whole_program_residual.rs").read_text().lower()
    for name in ("sum-dense", "branch-mix", "dot-product", "list-update"):
        if name in support:
            raise ResidualError("generic residual lowering dispatches on a kernel identity")
    combined = b"".join(
        (root / path).read_bytes().lower()
        for path in (
            "naux-lang/examples/naux_s4_structural_residual.rs",
            "naux-lang/examples/support/s4_whole_program_residual.rs",
        )
    )
    text = combined.decode("utf-8")
    for token in FORBIDDEN_TIMING:
        if token in text:
            raise ResidualError(f"timing token entered WP5B authority: {token}")
    for oracle in ("6710476800", "-69189632", "73294064435200", "6730547200"):
        if oracle in support:
            raise ResidualError("generic residual lowering contains a frozen checksum oracle")


def _pack_u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _pack_u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def _pack_string(value: str) -> bytes:
    raw = value.encode()
    return _pack_u32(len(raw)) + raw


def _op(row: list[str], ordinal: int, ip: int) -> tuple[str, ...]:
    if len(row) < 4 or row[:3] != ["op", f"{ordinal:02}", f"{ip:04}"]:
        raise ResidualError("residual op sequence is not canonical")
    name, args = row[3], row[4:]
    arity = {
        "const-i64": 1, "load-local": 1, "store-local": 1, "store-local-keep": 1,
        "add-local-const": 2, "add": 0, "sub": 0, "mul": 0, "div": 0,
        "mod": 0, "xor": 0, "shl": 0, "eq": 0, "ne": 0, "gt": 0, "ge": 0,
        "lt": 0, "le": 0, "and": 0, "or": 0, "jump": 1, "jump-if-false": 1,
        "range-allocate-init": 1, "list-length-static": 2, "list-load": 0,
        "list-store": 0, "release-list": 1, "return": 0,
    }
    if name not in arity or len(args) != arity[name]:
        raise ResidualError(f"unsupported or malformed residual op: {name}")
    for index, arg in enumerate(args):
        if name in ("const-i64", "add-local-const") and index == len(args) - 1:
            _sint(arg, name)
        elif name == "range-allocate-init" or (name == "list-length-static" and index == 1):
            _uint(arg, name)
        else:
            _uint(arg, name, (1 << 32) - 1)
    return tuple([name, *args])


def parse_candidate(raw: bytes, contract: Contract) -> Candidate:
    lines = _canonical(raw, "structural residual candidate", MAX_CANDIDATE_BYTES)
    if len(lines) < 10 or lines[:5] != [
        CANDIDATE_MAGIC,
        "meta\tstatus\tstructural-residual-admitted",
        "meta\tnative-status\tunavailable",
        "meta\ttiming-status\tforbidden",
        COLUMNS,
    ] or lines[-1] != "verification\tregenerated":
        raise ResidualError("structural residual candidate envelope drifted")
    if any(token in raw.lower().decode() for token in FORBIDDEN_TIMING):
        raise ResidualError("timing vocabulary entered residual candidate")
    cursor = 5
    kernels = []
    for record in contract.records:
        fields = lines[cursor].split("\t")
        cursor += 1
        if len(fields) != 16 or fields[0] != "kernel":
            raise ResidualError("invalid residual kernel header")
        ordinal = _ordinal(fields[1], "candidate ordinal")
        if ordinal != record.ordinal or fields[2] != record.name:
            raise ResidualError("candidate kernel identity drifted")
        residual_hash = _hash(fields[3], "candidate residual hash")
        witness_hash = _hash(fields[4], "candidate witness hash")
        local_count, n_local, reps_local, list_local, checksum_local = (
            _uint(value, "kernel local", (1 << 32) - 1) for value in fields[5:10]
        )
        n = _uint(fields[10], "kernel n")
        reps = _uint(fields[11], "kernel reps")
        op_count = _uint(fields[12], "kernel op count", 10_000)
        traversal = _uint(fields[13], "kernel traversal")
        loads = _uint(fields[14], "kernel list loads", (1 << 32) - 1)
        stores = _uint(fields[15], "kernel list stores", (1 << 32) - 1)
        if op_count != record.op_count or stores != record.list_stores or traversal != n * reps:
            raise ResidualError("candidate static work counts drifted")
        ops = []
        for ip in range(op_count):
            ops.append(_op(lines[cursor].split("\t"), ordinal, ip))
            cursor += 1
        witness_fields = lines[cursor].split("\t")
        cursor += 1
        if len(witness_fields) != 18 or witness_fields[:2] != ["witness", f"{ordinal:02}"]:
            raise ResidualError("invalid residual witness row")
        witness_values = witness_fields[2:]
        witness = tuple(
            _uint(value, "witness integer", (1 << 64) - 1 if index in (6, 11, 12) else (1 << 32) - 1)
            for index, value in enumerate(witness_values)
        )
        kernel = Kernel(ordinal, record.name, residual_hash, witness_hash, local_count, n_local, reps_local, list_local, checksum_local, n, reps, tuple(ops), witness)
        _verify_kernel(kernel, loads, stores)
        if _residual_hash(kernel) != residual_hash or _witness_hash(witness) != witness_hash:
            raise ResidualError("independent residual hash replay disagrees")
        if residual_hash != record.residual_hash or witness_hash != record.witness_hash:
            raise ResidualError("candidate differs from sealed structural residual")
        kernels.append(kernel)
    if cursor != len(lines) - 1:
        raise ResidualError("candidate contains trailing rows")
    return Candidate(tuple(kernels), raw)


def _residual_hash(kernel: Kernel) -> str:
    raw = b"".join(
        _pack_u32(value)
        for value in (kernel.local_count, kernel.n_local, kernel.reps_local, kernel.list_local, kernel.checksum_local)
    )
    raw += _pack_u64(kernel.n) + _pack_u64(kernel.reps) + _pack_u32(len(kernel.ops))
    raw += b"".join(_pack_string("\t".join(op)) for op in kernel.ops)
    return _sha256(RESIDUAL_DOMAIN + raw)


def _witness_hash(witness: tuple[int, ...]) -> str:
    allocation, release, oh, oe, ob, oc, obound, ih, ie, ib, ic, ibound, traversal, loads, stores, checksum = witness
    raw = _pack_u32(allocation) + _pack_u32(release)
    raw += b"".join(_pack_u32(value) for value in (oh, oe, ob, oc)) + _pack_u64(obound)
    raw += b"".join(_pack_u32(value) for value in (ih, ie, ib, ic)) + _pack_u64(ibound)
    raw += _pack_u64(traversal) + _pack_u32(loads) + _pack_u32(stores) + _pack_u32(checksum)
    return _sha256(WITNESS_DOMAIN + raw)


def _verify_kernel(kernel: Kernel, declared_loads: int, declared_stores: int) -> None:
    ops = kernel.ops
    if not ops or any(local >= kernel.local_count for local in (kernel.n_local, kernel.reps_local, kernel.list_local, kernel.checksum_local)):
        raise ResidualError("invalid residual locals")
    witness = kernel.witness
    allocation, release, oh, oe, ob, oc, obound, ih, ie, ib, ic, ibound, traversal, loads, stores, checksum = witness
    if any(index >= len(ops) for index in (allocation, release, oh, oe, ob, ih, ie, ib)):
        raise ResidualError("work witness instruction index is out of range")
    if not (oh < ih < ib < ie <= ob < oe) or (obound, ibound, traversal) != (kernel.reps, kernel.n, kernel.n * kernel.reps):
        raise ResidualError("nested traversal witness drifted")
    if (loads, stores, checksum) != (declared_loads, declared_stores, kernel.checksum_local):
        raise ResidualError("work witness counts drifted")
    if ops[allocation] != ("range-allocate-init", str(kernel.n)) or ops[allocation + 1] != ("store-local", str(kernel.list_local)):
        raise ResidualError("allocation witness does not replay")
    if release != oe or ops[release] != ("release-list", str(kernel.list_local)):
        raise ResidualError("teardown witness does not replay")
    if ops[release + 1 :] != (("load-local", str(kernel.checksum_local)), ("return",)):
        raise ResidualError("checksum return does not follow teardown")
    if ops[oh : oh + 4] != (("load-local", str(oc)), ("load-local", str(kernel.reps_local)), ("lt",), ("jump-if-false", str(oe))):
        raise ResidualError("outer guard does not replay")
    if ops[ih : ih + 4] != (("load-local", str(ic)), ("list-length-static", str(kernel.list_local), str(kernel.n)), ("lt",), ("jump-if-false", str(ie))):
        raise ResidualError("inner guard does not replay")
    if ops[ob] != ("jump", str(oh)) or ops[ib] != ("jump", str(ih)):
        raise ResidualError("loop backedge does not replay")
    if not _zero_init(ops[:oh], oc) or not _zero_init(ops[oh + 4 : ih], ic):
        raise ResidualError("loop counter initialization is absent")
    if not _unit_increment(ops[ie:ob], oc) or not _unit_increment(ops[ih + 4 : ib], ic):
        raise ResidualError("loop counter increment is absent")
    actual_loads = sum(op[0] == "list-load" for op in ops)
    actual_stores = sum(op[0] == "list-store" for op in ops)
    if (actual_loads, actual_stores) != (loads, stores) or actual_loads == 0:
        raise ResidualError("list kernel operation counts drifted")
    for ip, op in enumerate(ops):
        if op[0] in ("list-load", "list-store") and not ih + 4 <= ip < ib:
            raise ResidualError("list operation escaped inner traversal")
    _verify_stack(ops)


def _zero_init(ops: tuple[tuple[str, ...], ...], local: int) -> bool:
    return any(a == ("const-i64", "0") and b == ("store-local", str(local)) for a, b in zip(ops, ops[1:]))


def _unit_increment(ops: tuple[tuple[str, ...], ...], local: int) -> bool:
    if ("add-local-const", str(local), "1") in ops:
        return True
    pattern = (("load-local", str(local)), ("const-i64", "1"), ("add",), ("store-local", str(local)))
    return any(ops[index : index + 4] == pattern for index in range(max(0, len(ops) - 3)))


def _verify_stack(ops: tuple[tuple[str, ...], ...]) -> None:
    push = {"const-i64", "load-local", "range-allocate-init", "list-length-static"}
    binary = {"add", "sub", "mul", "div", "mod", "xor", "shl", "eq", "ne", "gt", "ge", "lt", "le", "and", "or", "list-load"}
    depths: list[int | None] = [None] * len(ops)
    depths[0] = 0
    queue = [0]
    while queue:
        ip = queue.pop(0)
        depth = depths[ip]
        assert depth is not None
        name = ops[ip][0]
        required, delta = ((0, 1) if name in push else (1, -1) if name in ("store-local", "jump-if-false", "return") else (2, -1) if name in binary else (3, -2) if name == "list-store" else (1, 0) if name == "store-local-keep" else (0, 0))
        if depth < required:
            raise ResidualError(f"stack underflow at residual instruction {ip}")
        next_depth = depth + delta
        if name == "return":
            if next_depth != 0:
                raise ResidualError("return leaves residual stack values")
            successors = ()
        elif name == "jump":
            successors = (_uint(ops[ip][1], "jump target", len(ops) - 1),)
        elif name == "jump-if-false":
            successors = (_uint(ops[ip][1], "jump target", len(ops) - 1), ip + 1)
        elif ip + 1 < len(ops):
            successors = (ip + 1,)
        else:
            raise ResidualError("residual falls off the end")
        for target in successors:
            if target >= len(ops):
                raise ResidualError("residual jump is out of range")
            if depths[target] is not None and depths[target] != next_depth:
                raise ResidualError("residual stack merge disagrees")
            if depths[target] is None:
                depths[target] = next_depth
                queue.append(target)
    if any(depth is None for depth in depths):
        raise ResidualError("residual contains unreachable instructions")


def _run(binary: Path) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([os.fspath(binary)], input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30)


def validate(root: Path) -> Admission:
    parent = wp5a.validate(root)
    if parent.authority.seal != WP5A_AUTHORITY_SEAL:
        raise ResidualError("WP5A parent authority is not the accepted root")
    contract = parse_contract(root / "distribution/s4-performance/WP5B-RESIDUAL.tsv")
    authority = parse_authority(root / "distribution/s4-performance/WP5B-AUTHORITY.tsv", contract.seal)
    _verify_files(root, authority)
    _verify_source_boundary(root)
    lines = [
        REPORT_MAGIC,
        "residual-status\tstructural-residual-admitted",
        "native-status\tunavailable",
        "claim-status\tnot-admitted",
        "timing-status\tforbidden",
        "mode\tstatic",
        f"wp5a-authority-seal\t{WP5A_AUTHORITY_SEAL}",
        f"contract-seal\t{contract.seal}",
        f"wp5b-authority-seal\t{authority.seal}",
        f"files\t{len(authority.files)}",
        "kernels\t4",
        "blocker\tmachine-ir-lowering-unavailable",
        "blocker\telf-process-parity-unavailable",
        "blocker\tnaux-residual-role-admission-unavailable",
    ]
    body = "".join(f"{line}\n" for line in lines).encode()
    root_hash = _sha256(REPORT_DOMAIN + body)
    report = body + f"report-root\t{root_hash}\n".encode()
    return Admission(contract, authority, report, root_hash)


def replay(root: Path, admission: Admission, binary: Path) -> tuple[bytes, Candidate]:
    runs = []
    for _ in range(2):
        completed = _run(binary)
        if completed.returncode != 0 or completed.stderr:
            raise ResidualError("structural residual emitter failed closed replay")
        runs.append(parse_candidate(completed.stdout, admission.contract))
    if runs[0] != runs[1]:
        raise ResidualError("structural residual regeneration is nondeterministic")
    lines = [
        REPORT_MAGIC,
        "residual-status\tstructural-residual-admitted",
        "native-status\tunavailable",
        "claim-status\tnot-admitted",
        "timing-status\tforbidden",
        "mode\tuntimed-structural-replay",
        f"wp5b-authority-seal\t{admission.authority.seal}",
        f"candidate-root\t{_sha256(runs[0].raw)}",
        "replays\t2",
        "kernels\t4",
        "blocker\tmachine-ir-lowering-unavailable",
        "blocker\telf-process-parity-unavailable",
        "blocker\tnaux-residual-role-admission-unavailable",
    ]
    body = "".join(f"{line}\n" for line in lines).encode()
    report_root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{report_root}\n".encode(), runs[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    try:
        admission = validate(args.root.resolve())
        if args.binary is None:
            sys.stdout.buffer.write(admission.report)
        else:
            report, _candidate = replay(args.root.resolve(), admission, args.binary.resolve())
            sys.stdout.buffer.write(report)
    except (OSError, ResidualError, wp5a.RequestError) as error:
        print(f"S4-WP5B validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
