#!/usr/bin/env python3
"""Validate or run the clock-free S4-WP8A performance-gap forensics gate."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_residual_elf64 as wp5d
import s4_residual_process as wp5e
import s4_residual_timing as wp7b
import s4_threshold_evaluator as wp7d


CONTRACT_MAGIC = "NAUX-S4-PERFORMANCE-GAP-FORENSICS-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-PERFORMANCE-GAP-FORENSICS-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-PERFORMANCE-GAP-FORENSICS-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-performance-gap-forensics:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-performance-gap-forensics:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-performance-gap-forensics:report:v1\0"
WP5D_AUTHORITY_SEAL = "eba915d65c448d0251c4b253c911d61e2f06b8d4bcc4cf3e57a7eea78bd87fb4"
WP5E_AUTHORITY_SEAL = "098a7cb2216359c03ab1e58d3a41f6c904d411ccafa1c10b0a88885fc3dfc53f"
WP7B_AUTHORITY_SEAL = "dbde9cb35d1687b47f7e3c96081bc2d62e750013656ba7ba57933f0f186661ed"
WP7D_AUTHORITY_SEAL = "be68151c8af3a32ddd09e1390b354c8dfa8679476af7143e937252b07b148179"
SOURCE_COMMIT = "7d270a54c0af7530585fde7be4d9f3f67c15e142"
HOST_REPORT_ROOT = "d76ec487c0a9d9d3456f6af8bf1d5c7ec11d4e457e84e624a2ddaa7a054402d8"
BUNDLE_ROOT = "3b28e2d8c1c73af037c7455a5e81bf788d3301620c53979bb7f2d5c3d6e95e6b"
EVIDENCE_ROOT = "0b645e70e9e84f1e28dc901cc704e49bd14e71ec9d2a61d6888e58120188edba"
THRESHOLD_CANDIDATE_ROOT = "bd716964a55ba03127e1ef80e9cabfccaee68bf78af9ea72cd8f76eecbf361f2"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
MAX_REPORT_BYTES = 2_000_000
MAX_STEPS = 100_000_000

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-wp5d-authority", WP5D_AUTHORITY_SEAL),
    ("parent-wp5e-authority", WP5E_AUTHORITY_SEAL),
    ("parent-wp7b-authority", WP7B_AUTHORITY_SEAL),
    ("parent-wp7d-authority", WP7D_AUTHORITY_SEAL),
    ("source-commit", SOURCE_COMMIT),
    ("host-report-root", HOST_REPORT_ROOT),
    ("bundle-root", BUNDLE_ROOT),
    ("evidence-root", EVIDENCE_ROOT),
    ("threshold-candidate-root", THRESHOLD_CANDIDATE_ROOT),
    ("threshold-candidate", "fail"),
    ("claim-status", "not-admitted"),
    ("clock-policy", "forbidden"),
    ("native-execution-policy", "forbidden"),
    ("artifact-chain", "wp7b-timing-to-wp5e-process-to-wp5d-target"),
    ("decoder", "owned-wp5d-range-replay"),
    ("profile", "bounded-target-plan-interpretation"),
    ("metric", "structural-exposure-not-cycles"),
    ("kernel-count", "4"),
)
CONTRACT_GATES = (
    ("01", "immutable-bundle", "required", "exact-first-wp7c-root"),
    ("02", "threshold-replay", "required", "exact-failed-wp7d-candidate"),
    ("03", "timing-artifact", "required", "exact-four-wp7b-images"),
    ("04", "process-target", "required", "exact-four-wp5e-reconstructions"),
    ("05", "target-decode", "required", "exact-wp5d-ranges-and-bytes"),
    ("06", "source-binding", "required", "exact-wp5c-correspondence"),
    ("07", "bounded-profile", "required", "oracle-and-owner-state"),
    ("08", "candidate-ranking", "required", "structural-facts-only"),
    ("09", "claim-boundary", "required", "not-admitted"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8A"),
    ("authority-id", "s4-performance-gap-forensics-v1"),
    ("status", "forensics-protocol-admitted"),
    ("claim-status", "not-admitted"),
    ("clock-policy", "forbidden"),
    ("native-execution-policy", "forbidden"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-performance-gap-forensics.yml",
    "distribution/s4-performance/WP8A-FORENSICS.tsv",
    "distribution/s4-performance/WP8A-NONCLAIMS.md",
    "distribution/s4-performance/WP8A-README.md",
    "scripts/s4_performance_gap_forensics.py",
    "scripts/tests/test_s4_performance_gap_forensics_replay.py",
    "scripts/tests/test_s4_performance_gap_forensics_static.py",
)


class ForensicsError(RuntimeError):
    """A fail-closed S4-WP8A validation or replay error."""


@dataclass(frozen=True)
class Contract:
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
    wp5d_admission: wp5d.Admission
    wp5e_admission: wp5e.Admission
    wp7b_admission: wp7b.Admission
    wp7d_admission: wp7d.Admission


@dataclass(frozen=True)
class Profile:
    result: int
    steps: int
    block_visits: tuple[int, ...]
    operation_visits: tuple[tuple[int, ...], ...]
    terminator_visits: tuple[int, ...]


@dataclass(frozen=True)
class BoundKernel:
    wp5d_kernel: wp5d.Kernel
    timing_record: wp7b.ContractRecord
    process_record: wp5e.ContractRecord
    artifact: bytes
    process_target: bytes


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(raw: bytes, label: str, maximum: int = MAX_REPORT_BYTES) -> list[str]:
    if not raw or len(raw) > maximum or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise ForensicsError(f"{label} has invalid extent or encoding")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ForensicsError(f"{label} is not UTF-8") from error
    lines = text.splitlines()
    if any(not line or line != line.strip() for line in lines):
        raise ForensicsError(f"{label} contains blank or padded rows")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise ForensicsError(f"cannot read {path.name}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ForensicsError(f"{path.name} is not a regular file")
    lines = _canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise ForensicsError(f"{path.name} magic or shape drifted")
    fields = lines[-1].split("\t")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if (
        len(fields) != 2
        or not HASH_RE.fullmatch(fields[1])
        or _sha256(domain + body) != fields[1]
    ):
        raise ForensicsError(f"{path.name} seal mismatch")
    return lines[1:-1], fields[1]


def _take(lines: list[str], index: int, tag: str, width: int) -> tuple[list[tuple[str, ...]], int]:
    rows: list[tuple[str, ...]] = []
    while index < len(lines) and lines[index].startswith(f"{tag}\t"):
        fields = lines[index].split("\t")
        if len(fields) != width:
            raise ForensicsError(f"WP8A {tag} row is malformed")
        rows.append(tuple(fields[1:]))
        index += 1
    return rows, index


def parse_contract(path: Path) -> Contract:
    lines, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    metadata, index = _take(lines, 0, "meta", 3)
    gates, index = _take(lines, index, "gate", 5)
    if tuple(metadata) != CONTRACT_METADATA or tuple(gates) != CONTRACT_GATES or index != len(lines):
        raise ForensicsError("WP8A contract metadata, gates, or extent drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    metadata, index = _take(lines, 0, "meta", 3)
    if tuple(metadata) != AUTHORITY_METADATA:
        raise ForensicsError("WP8A authority metadata drifted")
    expected_links = (
        f"component\tforensics-contract\tdistribution/s4-performance/WP8A-FORENSICS.tsv\t{contract_seal}",
        f"parent\twp5d-authority\tdistribution/s4-performance/WP5D-AUTHORITY.tsv\t{WP5D_AUTHORITY_SEAL}",
        f"parent\twp5e-authority\tdistribution/s4-performance/WP5E-AUTHORITY.tsv\t{WP5E_AUTHORITY_SEAL}",
        f"parent\twp7b-authority\tdistribution/s4-performance/WP7B-AUTHORITY.tsv\t{WP7B_AUTHORITY_SEAL}",
        f"parent\twp7d-authority\tdistribution/s4-performance/WP7D-AUTHORITY.tsv\t{WP7D_AUTHORITY_SEAL}",
    )
    if tuple(lines[index:index + len(expected_links)]) != expected_links:
        raise ForensicsError("WP8A component or parent binding drifted")
    index += len(expected_links)
    files: list[FileRecord] = []
    while index < len(lines):
        fields = lines[index].split("\t")
        if (
            len(fields) != 6
            or fields[0] != "file"
            or not MODE_RE.fullmatch(fields[1])
            or not UINT_RE.fullmatch(fields[2])
            or not HASH_RE.fullmatch(fields[3])
            or fields[4] not in EXPECTED_FILES
            or fields[5] != "performance-gap-forensics"
        ):
            raise ForensicsError("WP8A authority file row is malformed")
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
        index += 1
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise ForensicsError("WP8A authority file inventory drifted")
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ForensicsError(f"bound file is not regular: {record.path}")
        raw = path.read_bytes()
        if stat.S_IMODE(metadata.st_mode) != record.mode & 0o777 or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise ForensicsError(f"bound file drifted: {record.path}")


def _verify_static_boundary(root: Path) -> None:
    source = (root / "scripts/s4_performance_gap_forensics.py").read_text()
    forbidden = (
        "time." + "time(",
        "perf_" + "counter(",
        "clock_" + "gettime(",
        "requests." + "get(",
        "urllib." + "request",
        "obj" + "dump",
        "llvm-" + "obj" + "dump",
    )
    if any(token in source for token in forbidden):
        raise ForensicsError("WP8A source crossed the clock, network, or foreign-decoder boundary")


def _static_report(contract: Contract, authority: Authority) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        "status\tforensics-protocol-admitted",
        "mode\tstatic-no-bundle-no-clock-no-execution",
        "threshold-candidate\tfail",
        "claim-status\tnot-admitted",
        "blockers\t2",
        "blocker\texact-immutable-bundle-required",
        "blocker\treviewed-wp5d-emitter-required",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    wp5d_admission = wp5d.validate(root)
    wp5e_admission = wp5e.validate(root)
    wp7b_admission = wp7b.validate(root)
    wp7d_admission = wp7d.validate(root)
    if (
        wp5d_admission.authority.seal != WP5D_AUTHORITY_SEAL
        or wp5e_admission.authority.seal != WP5E_AUTHORITY_SEAL
        or wp7b_admission.authority.seal != WP7B_AUTHORITY_SEAL
        or wp7d_admission.authority.seal != WP7D_AUTHORITY_SEAL
    ):
        raise ForensicsError("WP8A parent authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP8A-FORENSICS.tsv")
    authority = parse_authority(root / "distribution/s4-performance/WP8A-AUTHORITY.tsv", contract.seal)
    _verify_files(root, authority)
    _verify_static_boundary(root)
    report, report_root = _static_report(contract, authority)
    return Admission(
        contract,
        authority,
        report,
        report_root,
        wp5d_admission,
        wp5e_admission,
        wp7b_admission,
        wp7d_admission,
    )


def _regular_binary(path: Path, maximum: int) -> bytes:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ForensicsError(f"measured artifact is not regular: {path.name}")
    raw = path.read_bytes()
    if not raw or len(raw) > maximum:
        raise ForensicsError(f"measured artifact extent drifted: {path.name}")
    return raw


def bind_artifact_chain(
    artifacts: tuple[bytes, ...],
    candidate: wp5d.Candidate,
    timing_contract: wp7b.Contract,
    process_contract: wp5e.Contract,
) -> tuple[BoundKernel, ...]:
    if not (
        len(artifacts)
        == len(candidate.kernels)
        == len(timing_contract.records)
        == len(process_contract.records)
        == 4
    ):
        raise ForensicsError("WP8A artifact-chain cardinality drifted")
    result: list[BoundKernel] = []
    for artifact, target_kernel, timing, process in zip(
        artifacts,
        candidate.kernels,
        timing_contract.records,
        process_contract.records,
        strict=True,
    ):
        if not (
            target_kernel.record.ordinal == timing.ordinal == process.ordinal
            and target_kernel.record.name == timing.name == process.name
        ):
            raise ForensicsError("WP8A artifact-chain kernel identity drifted")
        if (
            len(artifact) != timing.elf_bytes
            or _sha256(artifact) != timing.elf_hash
            or artifact[:4] != b"\x7fELF"
        ):
            raise ForensicsError(f"{timing.name} measured WP7B artifact drifted")
        process_target = artifact[timing.target_offset:]
        if (
            len(process_target) != timing.target_bytes
            or _sha256(process_target) != timing.target_hash
            or timing.target_hash != process.process_target_hash
            or timing.target_bytes != process.process_target_bytes
            or target_kernel.record.target_hash != process.parent_target_hash
            or target_kernel.record.target_bytes != process.parent_target_bytes
        ):
            raise ForensicsError(f"{timing.name} WP7B/WP5E/WP5D identity drifted")
        reconstructed = wp5e._reconstruct_process_target(process, target_kernel.target)
        if reconstructed != process_target:
            raise ForensicsError(f"{timing.name} WP5E reconstruction differs from measured target")
        if wp7b._reconstruct_elf(timing, process_target) != artifact:
            raise ForensicsError(f"{timing.name} WP7B reconstruction differs from measured artifact")
        result.append(BoundKernel(target_kernel, timing, process, artifact, process_target))
    return tuple(result)


def _i64(value: int) -> int:
    value &= (1 << 64) - 1
    return value - (1 << 64) if value >= 1 << 63 else value


def _home(values: dict[str, object], name: str) -> object:
    if name not in values:
        raise ForensicsError(f"target-plan read undefined home {name}")
    return values[name]


def _integer(values: dict[str, object], name: str) -> int:
    value = _home(values, name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ForensicsError(f"target-plan home {name} is not i64")
    return value


def _handle(values: dict[str, object], name: str) -> tuple[str, int]:
    value = _home(values, name)
    if not (
        isinstance(value, tuple)
        and len(value) == 2
        and value[0] == "list"
        and isinstance(value[1], int)
    ):
        raise ForensicsError(f"target-plan home {name} is not an owned list handle")
    return value


def interpret_plan(kernel: wp5d.Kernel, oracle: int) -> Profile:
    values: dict[str, object] = {}
    heap: dict[int, list[int]] = {}
    next_handle = 1
    block_visits = [0] * len(kernel.blocks)
    operation_visits = [[0] * len(block.operations) for block in kernel.blocks]
    terminator_visits = [0] * len(kernel.blocks)
    block_id = 0
    steps = 0
    while True:
        if steps >= MAX_STEPS or block_id >= len(kernel.blocks):
            raise ForensicsError(f"{kernel.record.name} target-plan exceeded its bounded control envelope")
        block = kernel.blocks[block_id]
        if block.block_id != block_id:
            raise ForensicsError("target-plan blocks are not canonical contiguous ids")
        block_visits[block_id] += 1
        for ordinal, operation in enumerate(block.operations):
            operation_visits[block_id][ordinal] += 1
            steps += 1
            opcode = operation[0]
            if opcode == "const-i64" and len(operation) == 3:
                values[operation[1]] = _i64(int(operation[2]))
            elif opcode == "copy" and len(operation) == 3:
                values[operation[1]] = _home(values, operation[2])
            elif opcode == "store-slot" and len(operation) == 3:
                values[operation[1]] = _home(values, operation[2])
            elif opcode == "add-slot-const" and len(operation) == 3:
                values[operation[1]] = _i64(_integer(values, operation[1]) + int(operation[2]))
            elif opcode in {"i64-add", "i64-sub", "i64-mul"} and len(operation) == 4:
                left = _integer(values, operation[2])
                right = _integer(values, operation[3])
                raw = left + right if opcode == "i64-add" else left - right if opcode == "i64-sub" else left * right
                values[operation[1]] = _i64(raw)
            elif opcode in {"i64-eq", "i64-ne", "i64-gt", "i64-ge", "i64-lt", "i64-le"} and len(operation) == 4:
                left = _integer(values, operation[2])
                right = _integer(values, operation[3])
                comparisons = {
                    "i64-eq": left == right,
                    "i64-ne": left != right,
                    "i64-gt": left > right,
                    "i64-ge": left >= right,
                    "i64-lt": left < right,
                    "i64-le": left <= right,
                }
                values[operation[1]] = comparisons[opcode]
            elif opcode == "range-allocate-init" and len(operation) == 3:
                length = int(operation[2])
                handle = next_handle
                next_handle += 1
                heap[handle] = list(range(length))
                values[operation[1]] = ("list", handle)
            elif opcode == "list-length-static" and len(operation) == 3:
                values[operation[1]] = int(operation[2])
            elif opcode == "list-load-checked" and len(operation) == 5:
                handle = _handle(values, operation[2])[1]
                index = _integer(values, operation[3])
                length = int(operation[4])
                if handle not in heap or index < 0 or index >= length or len(heap[handle]) != length:
                    raise ForensicsError("target-plan list load escaped its exact bounds")
                values[operation[1]] = heap[handle][index]
            elif opcode == "list-store-checked" and len(operation) == 6:
                handle_value = _handle(values, operation[2])
                index = _integer(values, operation[3])
                value = _integer(values, operation[4])
                length = int(operation[5])
                handle = handle_value[1]
                if handle not in heap or index < 0 or index >= length or len(heap[handle]) != length:
                    raise ForensicsError("target-plan list store escaped its exact bounds")
                heap[handle][index] = value
                values[operation[1]] = handle_value
            elif opcode == "release-owned-list" and len(operation) == 3:
                handle = _handle(values, operation[1])[1]
                if len(heap.get(handle, ())) != int(operation[2]):
                    raise ForensicsError("target-plan release length drifted")
                del heap[handle]
                values[operation[1]] = 0
            else:
                raise ForensicsError(f"unsupported target-plan operation {operation!r}")
        terminator_visits[block_id] += 1
        steps += 1
        terminator = block.terminator
        if terminator[0] == "goto" and len(terminator) == 2:
            block_id = int(terminator[1][1:])
        elif terminator[0] == "branch" and len(terminator) == 4:
            condition = _home(values, terminator[1])
            if not isinstance(condition, bool):
                raise ForensicsError("target-plan branch condition is not bool")
            block_id = int((terminator[2] if condition else terminator[3])[1:])
        elif terminator[0] == "return" and len(terminator) == 2:
            result = _integer(values, terminator[1])
            if result != oracle or heap:
                raise ForensicsError(f"{kernel.record.name} oracle or owner-state replay failed")
            return Profile(
                result,
                steps,
                tuple(block_visits),
                tuple(tuple(row) for row in operation_visits),
                tuple(terminator_visits),
            )
        else:
            raise ForensicsError("unsupported target-plan terminator")


def _operation_facts(operation: tuple[str, ...]) -> tuple[str, int, int, int, int, int, int]:
    opcode = operation[0]
    if opcode == "const-i64":
        return "constant", 0, 1, 0, 0, 0, 0
    if opcode in {"copy", "store-slot"}:
        return "stack-transfer", 1, 1, 0, 0, 0, 0
    if opcode == "add-slot-const":
        return "scalar-update", 1, 1, 0, 0, 0, 0
    if opcode.startswith("i64-"):
        category = "scalar-compare" if opcode.split("-", 1)[1] in {"eq", "ne", "gt", "ge", "lt", "le"} else "scalar-update"
        return category, 2, 1, 0, 0, 0, 0
    if opcode == "range-allocate-init":
        return "allocation", 0, 1, 0, int(operation[2]), 0, 1
    if opcode == "list-length-static":
        return "static-list-length", 0, 1, 0, 0, 0, 0
    if opcode == "list-load-checked":
        return "checked-list-load", 2, 1, 1, 0, 1, 0
    if opcode == "list-store-checked":
        return "checked-list-store", 3, 1, 0, 1, 1, 0
    if opcode == "release-owned-list":
        return "release", 1, 1, 0, 0, 0, 1
    raise ForensicsError(f"cannot classify target-plan operation {opcode}")


def _terminator_facts(terminator: tuple[str, ...]) -> tuple[int, int]:
    return (1, 1) if terminator[0] in {"branch", "return"} else (0, 1)


def _exact_ratio(left_num: int, left_den: int, right_num: int, right_den: int) -> tuple[int, int]:
    numerator = left_num * right_den
    denominator = left_den * right_num
    divisor = __import__("math").gcd(numerator, denominator)
    return numerator // divisor, denominator // divisor


def _analysis_report(
    admission: Admission,
    threshold: wp7d.BundleReplay,
    kernels: tuple[BoundKernel, ...],
) -> tuple[bytes, str]:
    if (
        threshold.manifest.root != BUNDLE_ROOT
        or threshold.manifest.source_commit != SOURCE_COMMIT
        or threshold.manifest.host_attestation != HOST_REPORT_ROOT
        or threshold.evidence.evidence_root != EVIDENCE_ROOT
        or threshold.candidate_root != THRESHOLD_CANDIDATE_ROOT
        or b"threshold-candidate\tfail\n" not in threshold.report
    ):
        raise ForensicsError("WP8A immutable measurement identity drifted")
    statistics = {(value.role, value.kernel): value for value in threshold.evidence.statistics}
    rows = [
        REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        "status\tevidence-bound-performance-gap-forensics",
        "mode\tclock-free-no-native-execution",
        f"source-commit\t{SOURCE_COMMIT}",
        f"host-report-root\t{HOST_REPORT_ROOT}",
        f"bundle-root\t{BUNDLE_ROOT}",
        f"evidence-root\t{EVIDENCE_ROOT}",
        f"threshold-candidate-root\t{THRESHOLD_CANDIDATE_ROOT}",
        "threshold-candidate\tfail",
        "metric\tstructural-exposure-not-cycles",
        "claim-status\tnot-admitted",
    ]
    candidate_scores = {
        "register-resident-hot-state": 0,
        "checked-list-proof-hoisting": 0,
        "loop-invariant-static-materialization": 0,
        "neutral-arithmetic-erasure": 0,
    }
    category_totals: dict[str, list[int]] = {}
    for bound in kernels:
        kernel = bound.wp5d_kernel
        profile = interpret_plan(kernel, bound.process_record.oracle)
        naux = statistics[("01", f"{bound.timing_record.ordinal:02}")]
        specialized = statistics[("03", f"{bound.timing_record.ordinal:02}")]
        ratio_num, ratio_den = _exact_ratio(
            naux.median_num,
            naux.median_den,
            specialized.median_num,
            specialized.median_den,
        )
        rows.append(
            f"kernel\t{bound.timing_record.ordinal:02}\t{bound.timing_record.name}\t"
            f"{kernel.record.machine_hash}\t{kernel.record.target_hash}\t"
            f"{bound.timing_record.elf_hash}\t{profile.result}\t{profile.steps}\t"
            f"{ratio_num}\t{ratio_den}\t{bound.timing_record.target_offset}\t"
            f"{bound.timing_record.target_bytes}\t{kernel.record.target_bytes}\t"
            f"{bound.process_record.process_target_bytes - bound.process_record.parent_target_bytes}"
        )
        ranges = {(value.block, value.ordinal, value.kind): value for value in kernel.encodings}
        mappings = {(value.block, value.machine_ordinal, value.kind): value.residual_ip for value in kernel.mappings}
        if len(ranges) != len(kernel.encodings) or len(mappings) != len(kernel.mappings):
            raise ForensicsError("WP8A range or correspondence key is not unique")
        for block in kernel.blocks:
            visits = profile.block_visits[block.block_id]
            rows.append(f"block\t{bound.timing_record.ordinal:02}\t{block.block_id}\t{visits}")
            constants: dict[str, int] = {}
            for ordinal, operation in enumerate(block.operations):
                visit_count = profile.operation_visits[block.block_id][ordinal]
                encoding = ranges.get((block.block_id, ordinal, "operation"))
                residual_ip = mappings.get((block.block_id, ordinal, "operation"))
                if encoding is None or residual_ip is None or encoding.end <= encoding.start:
                    raise ForensicsError("WP8A operation lacks exact encoding or source correspondence")
                byte_count = encoding.end - encoding.start
                category, stack_reads, stack_writes, heap_reads, heap_writes, bounds, syscalls = _operation_facts(operation)
                totals = category_totals.setdefault(category, [0] * 9)
                facts = (
                    1,
                    visit_count,
                    byte_count,
                    byte_count * visit_count,
                    stack_reads * visit_count,
                    stack_writes * visit_count,
                    heap_reads * visit_count,
                    heap_writes * visit_count,
                    bounds * visit_count,
                )
                for index, value in enumerate(facts):
                    totals[index] += value
                candidate_scores["register-resident-hot-state"] += (stack_reads + stack_writes) * visit_count
                candidate_scores["checked-list-proof-hoisting"] += bounds * visit_count
                if operation[0] in {"const-i64", "list-length-static"} and visit_count > 1:
                    candidate_scores["loop-invariant-static-materialization"] += visit_count
                if operation[0] == "const-i64":
                    constants[operation[1]] = int(operation[2])
                if operation[0] == "i64-add" and (
                    constants.get(operation[2]) == 0 or constants.get(operation[3]) == 0
                ):
                    candidate_scores["neutral-arithmetic-erasure"] += visit_count
                rows.append(
                    f"operation\t{bound.timing_record.ordinal:02}\t{block.block_id}\t{ordinal}\t"
                    f"{residual_ip}\t{category}\t{visit_count}\t{byte_count}\t"
                    f"{byte_count * visit_count}\t{stack_reads * visit_count}\t"
                    f"{stack_writes * visit_count}\t{heap_reads * visit_count}\t"
                    f"{heap_writes * visit_count}\t{bounds * visit_count}\t"
                    f"{syscalls * visit_count}\t{'|'.join(operation)}"
                )
            ordinal = len(block.operations)
            encoding = ranges.get((block.block_id, ordinal, "terminator"))
            residual_ip = mappings.get((block.block_id, ordinal, "terminator"))
            if encoding is None or encoding.end <= encoding.start:
                raise ForensicsError("WP8A terminator lacks an exact encoding range")
            if residual_ip is None and block.terminator[0] != "goto":
                raise ForensicsError("WP8A sourced terminator lacks exact correspondence")
            residual_label = "implicit" if residual_ip is None else str(residual_ip)
            visit_count = profile.terminator_visits[block.block_id]
            stack_reads, branches = _terminator_facts(block.terminator)
            byte_count = encoding.end - encoding.start
            candidate_scores["register-resident-hot-state"] += stack_reads * visit_count
            rows.append(
                f"terminator\t{bound.timing_record.ordinal:02}\t{block.block_id}\t{ordinal}\t"
                f"{residual_label}\t{visit_count}\t{byte_count}\t{byte_count * visit_count}\t"
                f"{stack_reads * visit_count}\t{branches * visit_count}\t{'|'.join(block.terminator)}"
            )
    for category, totals in sorted(category_totals.items(), key=lambda item: (-item[1][3], item[0])):
        rows.append(f"class\t{category}\t" + "\t".join(str(value) for value in totals))
    ranked = sorted(candidate_scores.items(), key=lambda item: (-item[1], item[0]))
    for ordinal, (name, score) in enumerate(ranked, 1):
        rows.append(f"candidate-rank\t{ordinal:02}\t{name}\t{score}\tstructural-dynamic-events\tnot-selected")
    rows.extend((
        "optimizer-selection\tforbidden-until-wp8b",
        "remeasurement\tforbidden-by-this-report",
        "claim-status\tnot-admitted",
    ))
    body = b"".join(f"{row}\n".encode() for row in rows)
    if len(body) > MAX_REPORT_BYTES:
        raise ForensicsError("WP8A report exceeds its bounded extent")
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def analyze(bundle: Path, emitter: Path, admission: Admission) -> tuple[bytes, str]:
    threshold = wp7d.replay_bundle(bundle, admission.wp7d_admission)
    _wp5d_report, candidate = wp5d.replay(admission.wp5d_admission, emitter)
    artifacts = tuple(
        _regular_binary(
            bundle / f"artifacts/01-naux-residual/{record.ordinal:02}-{record.name}",
            wp7b.MAX_ELF_BYTES,
        )
        for record in admission.wp7b_admission.contract.records
    )
    kernels = bind_artifact_chain(
        artifacts,
        candidate,
        admission.wp7b_admission.contract,
        admission.wp5e_admission.contract,
    )
    return _analysis_report(admission, threshold, kernels)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--emitter", type=Path)
    arguments = parser.parse_args(argv)
    try:
        admission = validate(arguments.root)
        if (arguments.bundle is None) != (arguments.emitter is None):
            raise ForensicsError("--bundle and --emitter must be provided together")
        if arguments.bundle is None:
            sys.stdout.buffer.write(admission.report)
        else:
            report, _root = analyze(arguments.bundle, arguments.emitter, admission)
            sys.stdout.buffer.write(report)
        return 0
    except (
        ForensicsError,
        wp5d.Elf64Error,
        wp5e.ProcessReplayError,
        wp7b.TimingReplayError,
        wp7d.ThresholdError,
        wp7d.wp1.AuthorityError,
        wp7d.wp7a.EvidenceError,
        wp7d.wp7c.RunnerError,
        wp7d.wp7a.wp6.HostControlError,
        OSError,
        ValueError,
    ) as error:
        print(f"S4-WP8A validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
