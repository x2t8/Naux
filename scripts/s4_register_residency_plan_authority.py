#!/usr/bin/env python3
"""Validate the S4-WP8C register-residency candidate-plan authority."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_contract as wp8b


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PLAN-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PLAN-AUTHORITY\t1"
PLAN_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PLAN\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PLAN-AUTHORITY-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-plan-contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-plan-authority:v1\0"
PLAN_REPORT_DOMAIN = b"NAUX:s4-register-residency-plan-report:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-plan-authority-report:v1\0"
CONTRACT_SEAL = "2669d74517889dc65ec25562e501d9ddb07da298966cc75644e8b20cd4bf0d47"
WP8B_CONTRACT_SEAL = "a84f27fd54793cb8d09ebd56d0733544203b84a1de66e05f07ea31c02d64edab"
WP8B_AUTHORITY_SEAL = "55bc1f788a1a4caad779049f9c0f0c6962c653b1a7091c821030b4ceac9c8733"
WP5D_SOURCE_SHA256 = "1424d65d5c108095b9179b1af7280c688d64dfd5006d1249c7ef6286e5a36a0f"
PLAN_REPORT_ROOT = "87e41ae9c0752ffe7738c8ea76e4df4d56751fc3a89f78cef8ece9e79083438e"
PLAN_REPORT_SHA256 = "42fcfa68e40631d0c4b578c67b87412bf6ae422ae751e7c5809e5f619d3b5174"
PLAN_REPORT_BYTES = 12_180
PLAN_REPORT_LINES = 276
MAX_FILE_BYTES = 1_000_000
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-wp8b-contract", WP8B_CONTRACT_SEAL),
    ("parent-wp8b-authority", WP8B_AUTHORITY_SEAL),
    ("frozen-wp5d-source-sha256", WP5D_SOURCE_SHA256),
    ("transform-id", "one-hot-loop-index-r12-v1"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("status", "candidate-plan-semantically-admitted"),
    ("implementation-status", "plan-only"),
    ("encoding-status", "forbidden"),
    ("native-execution-status", "forbidden"),
    ("measurement-status", "forbidden"),
    ("claim-status", "not-admitted"),
    ("plan-identity", "domain-separated-sha256-v1"),
    ("replay-identity", "domain-separated-sha256-v1"),
    ("report-identity", "domain-separated-sha256-v1"),
    ("replay-step-limit", "30000000"),
    ("report-root", PLAN_REPORT_ROOT),
    ("report-sha256", PLAN_REPORT_SHA256),
    ("report-bytes", str(PLAN_REPORT_BYTES)),
    ("report-lines", str(PLAN_REPORT_LINES)),
    ("kernel-count", "4"),
)
CONTRACT_GATES = (
    ("01", "parent-chain", "required", "exact-wp8b-contract-and-authority"),
    ("02", "baseline-source", "required", "exact-untouched-wp5d-source"),
    ("03", "report-identity", "required", "exact-domain-root-and-document-sha256"),
    ("04", "determinism", "required", "byte-identical-double-emission"),
    ("05", "promotion-cardinality", "required", "exactly-one-i64-slot-per-kernel"),
    ("06", "definite-initialization", "required", "forward-cfg-must-initialize-before-read"),
    ("07", "structural-erasure", "required", "reconstruct-complete-source-machine-ir"),
    ("08", "semantic-replay", "required", "independent-baseline-and-candidate-states"),
    ("09", "oracle-and-work", "required", "exact-result-and-step-count"),
    ("10", "overflow-and-ownership", "required", "exact-overflow-allocation-release-and-live-owner-state"),
    ("11", "abi-preservation", "required", "r12-save-restore-and-nonreturning-error"),
    ("12", "frame-boundary", "required", "unchanged-wp5d-frame"),
    ("13", "encoding-quarantine", "required", "no-candidate-machine-bytes"),
    ("14", "measurement-quarantine", "required", "no-wp7c-replacement-or-remeasurement"),
    ("15", "claim-boundary", "required", "not-admitted"),
)
EXPECTED_KERNELS = (
    ("01", "sum-dense", "97d8699e9449d53f4f3c9386839099be194b7db985709122092dfac3eacb8f2d", "98e3ac1191dbb078730f024f12a8f4b310f542bfed72830b32cfce127b705e27", "288", "s5", "i64", "r12", "3", "2", "7", "7a934673aedec04568958827fbd0a3c876dafe8d43d9ba46cb762f51fc340de3", "6710476800", "17204168", "0", "1", "1", "0", "r12-restored"),
    ("02", "branch-mix", "8095c962d36b2a6876770412feac0df8fdd5f4e3627481f97f6b78f9bc489888", "68ef1e141aac58454b2b1dde0bcf8d2ea100c4faa1ee43323ce121b6471a86ad", "352", "s6", "i64", "r12", "3", "2", "12", "c0dbaa15ff88b05f1936ced3013292d2093f33422cb4c85a46d9258b4589d369", "-69189632", "22406362", "0", "1", "1", "0", "r12-restored"),
    ("03", "dot-product", "b2fa698b60cb29e50d14e7f56650d1f09657562e3160e99bc7930e60f7c9e857", "c3a3bb75473b90689646c413552de32005ea27594d0565b72cc1984c731b7a3b", "288", "s5", "i64", "r12", "3", "2", "7", "c3850403ce4de28570939793eb48e07fe6a4731cafb01a5ae049d085a5f80a6c", "73294064435200", "15565768", "0", "1", "1", "0", "r12-restored"),
    ("04", "list-update", "c6ac1a97cad0ec0529e7f5f49bb91d316fa63a2b9abb2c7452a0040fe4150199", "de4e36706adc23c47bae3c95d0b45719867684423897b59b462e0cd937c6f982", "336", "s5", "i64", "r12", "4", "2", "7", "1038cd8fff86c8c4ec93e44031986f0848e0292ffa2fb8bb348b00c076e0bc42", "6730547200", "19661768", "0", "1", "1", "0", "r12-restored"),
)
EXPECTED_VERIFICATIONS = (
    "cfg-must-initialize-r12-before-every-read",
    "erasure-reconstructs-source-machine-ir",
    "independent-baseline-candidate-semantic-parity",
    "oracle-overflow-owner-state-and-r12-restore",
)
PLAN_METADATA = (
    ("status", "candidate-plan-only"),
    ("encoding-status", "unavailable"),
    ("execution-status", "semantic-replay-only"),
    ("measurement-status", "forbidden"),
    ("transform", "one-hot-loop-index-r12-v1"),
    ("parent-wp8b-contract", WP8B_CONTRACT_SEAL),
    ("parent-wp8b-authority", WP8B_AUTHORITY_SEAL),
    ("frozen-wp5d-source-sha256", WP5D_SOURCE_SHA256),
    ("plan-identity", "domain-separated-sha256-v1"),
    ("replay-identity", "domain-separated-sha256-v1"),
    ("report-identity", "domain-separated-sha256-v1"),
    ("replay-step-limit", "30000000"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8C"),
    ("authority-id", "s4-one-hot-loop-index-r12-plan-v1"),
    ("status", "candidate-plan-semantically-admitted"),
    ("implementation-status", "plan-only"),
    ("encoding-status", "forbidden"),
    ("native-execution-status", "forbidden"),
    ("measurement-status", "forbidden"),
    ("claim-status", "not-admitted"),
    ("file-count", "8"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-plan.yml",
    "distribution/s4-performance/WP8C-CANDIDATE-PLAN.tsv",
    "distribution/s4-performance/WP8C-NONCLAIMS.md",
    "distribution/s4-performance/WP8C-README.md",
    "naux-lang/examples/naux_s4_register_residency_plan.rs",
    "naux-lang/examples/support/s4_register_residency_plan.rs",
    "scripts/s4_register_residency_plan_authority.py",
    "scripts/tests/test_s4_register_residency_plan_authority.py",
)


class PlanAuthorityError(RuntimeError):
    """A fail-closed WP8C authority error."""


@dataclass(frozen=True)
class Contract:
    kernels: tuple[tuple[str, ...], ...]
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
class PlanReport:
    sha256: str
    root: str
    kernels: tuple[tuple[str, ...], ...]


@dataclass(frozen=True)
class Admission:
    contract: Contract
    authority: Authority
    plan: PlanReport
    report: bytes
    report_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_regular(path: Path, label: str) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise PlanAuthorityError(f"{label} is not regular")
    if before.st_size > MAX_FILE_BYTES:
        raise PlanAuthorityError(f"{label} exceeds the bounded input limit")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise PlanAuthorityError(f"{label} changed before open")
        raw = handle.read(MAX_FILE_BYTES + 1)
        after = os.fstat(handle.fileno())
    rebound = path.lstat()
    if (opened.st_dev, opened.st_ino, opened.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ) or len(raw) != after.st_size:
        raise PlanAuthorityError(f"{label} changed while read")
    if (
        stat.S_ISLNK(rebound.st_mode)
        or not stat.S_ISREG(rebound.st_mode)
        or (after.st_dev, after.st_ino) != (rebound.st_dev, rebound.st_ino)
    ):
        raise PlanAuthorityError(f"{label} pathname changed while read")
    if len(raw) > MAX_FILE_BYTES:
        raise PlanAuthorityError(f"{label} exceeds the bounded input limit")
    return raw


def _canonical(raw: bytes, label: str) -> list[str]:
    if not raw or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise PlanAuthorityError(f"{label} has invalid extent or encoding")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise PlanAuthorityError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise PlanAuthorityError(f"{label} contains blank or padded rows")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    lines = _canonical(_read_regular(path, path.name), path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise PlanAuthorityError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise PlanAuthorityError(f"{path.name} seal is malformed")
    if _sha256(domain + body) != fields[1]:
        raise PlanAuthorityError(f"{path.name} seal mismatch")
    return lines[1:-1], fields[1]


def _take(lines: list[str], index: int, tag: str, width: int) -> tuple[list[tuple[str, ...]], int]:
    rows: list[tuple[str, ...]] = []
    while index < len(lines) and lines[index].startswith(f"{tag}\t"):
        fields = lines[index].split("\t")
        if len(fields) != width:
            raise PlanAuthorityError(f"malformed WP8C {tag} row")
        rows.append(tuple(fields[1:]))
        index += 1
    return rows, index


def parse_contract(path: Path) -> Contract:
    lines, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    metadata, index = _take(lines, 0, "meta", 3)
    gates, index = _take(lines, index, "gate", 5)
    kernels, index = _take(lines, index, "kernel", 20)
    verifications, index = _take(lines, index, "verification", 2)
    if tuple(metadata) != CONTRACT_METADATA or tuple(gates) != CONTRACT_GATES:
        raise PlanAuthorityError("WP8C metadata or gates drifted")
    if tuple(kernels) != EXPECTED_KERNELS:
        raise PlanAuthorityError("WP8C kernel plan or replay evidence drifted")
    if tuple(row[0] for row in verifications) != EXPECTED_VERIFICATIONS or index != len(lines):
        raise PlanAuthorityError("WP8C verification surface drifted")
    if seal != CONTRACT_SEAL:
        raise PlanAuthorityError("WP8C accepted contract identity drifted")
    return Contract(tuple(kernels), seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    metadata, index = _take(lines, 0, "meta", 3)
    if tuple(metadata) != AUTHORITY_METADATA:
        raise PlanAuthorityError("WP8C authority metadata drifted")
    links = (
        f"component\tcandidate-plan\tdistribution/s4-performance/WP8C-CANDIDATE-PLAN.tsv\t{contract_seal}",
        f"parent\twp8b-contract\tdistribution/s4-performance/WP8B-REGISTER-RESIDENCY.tsv\t{WP8B_CONTRACT_SEAL}",
        f"parent\twp8b-authority\tdistribution/s4-performance/WP8B-AUTHORITY.tsv\t{WP8B_AUTHORITY_SEAL}",
        f"parent\twp5d-source\tnaux-lang/examples/support/s4_residual_x64_elf.rs\t{WP5D_SOURCE_SHA256}",
    )
    if tuple(lines[index : index + len(links)]) != links:
        raise PlanAuthorityError("WP8C component or parent binding drifted")
    index += len(links)
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
            or fields[5] != "register-residency-plan"
        ):
            raise PlanAuthorityError("WP8C authority file row is malformed")
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
        index += 1
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise PlanAuthorityError("WP8C authority inventory drifted")
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        raw = _read_regular(path, record.path)
        metadata = path.lstat()
        if (
            stat.S_IMODE(metadata.st_mode) != record.mode & 0o777
            or len(raw) != record.size
            or _sha256(raw) != record.sha256
        ):
            raise PlanAuthorityError(f"bound WP8C file drifted: {record.path}")


def _verify_parents(root: Path) -> None:
    parent = wp8b.validate(root)
    if parent.contract.seal != WP8B_CONTRACT_SEAL or parent.authority.seal != WP8B_AUTHORITY_SEAL:
        raise PlanAuthorityError("WP8C WP8B parent drifted")
    baseline = _read_regular(
        root / "naux-lang/examples/support/s4_residual_x64_elf.rs", "WP5D lowering source"
    )
    if _sha256(baseline) != WP5D_SOURCE_SHA256:
        raise PlanAuthorityError("WP8C frozen WP5D source drifted")


def _verify_static_boundary(root: Path) -> None:
    source = _read_regular(
        root / "scripts/s4_register_residency_plan_authority.py", "WP8C validator source"
    ).decode()
    forbidden = (
        "sub" + "process",
        "time." + "time(",
        "perf_" + "counter(",
        "sock" + "et",
        "requ" + "ests",
        "url" + "lib",
        "cty" + "pes",
    )
    if any(token in source for token in forbidden):
        raise PlanAuthorityError("WP8C validator crossed its static boundary")


def parse_plan_report(path: Path, contract: Contract) -> PlanReport:
    raw = _read_regular(path, "WP8C candidate report")
    if len(raw) != PLAN_REPORT_BYTES or _sha256(raw) != PLAN_REPORT_SHA256:
        raise PlanAuthorityError("WP8C candidate report document identity drifted")
    lines = _canonical(raw, "WP8C candidate report")
    if len(lines) != PLAN_REPORT_LINES or lines[0] != PLAN_MAGIC:
        raise PlanAuthorityError("WP8C candidate report shape drifted")
    expected_root_row = f"report-root\t{PLAN_REPORT_ROOT}"
    if lines[-1] != expected_root_row:
        raise PlanAuthorityError("WP8C candidate report root row drifted")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if _sha256(PLAN_REPORT_DOMAIN + body) != PLAN_REPORT_ROOT:
        raise PlanAuthorityError("WP8C candidate report root mismatch")

    payload = lines[1:-1]
    metadata, index = _take(payload, 0, "meta", 3)
    if tuple(metadata) != PLAN_METADATA:
        raise PlanAuthorityError("WP8C candidate report metadata drifted")

    observed: list[tuple[str, ...]] = []
    for expected in contract.kernels:
        if index >= len(payload):
            raise PlanAuthorityError("WP8C candidate report truncated before kernel")
        kernel_fields = payload[index].split("\t")
        kernel = tuple(kernel_fields[1:])
        if kernel_fields[0] != "kernel" or kernel != expected[:11]:
            raise PlanAuthorityError("WP8C candidate report kernel identity drifted")
        index += 1
        ordinal = expected[0]
        if index >= len(payload) or payload[index] != (
            f"abi\t{ordinal}\tsave-r12\trestore-r12\terror-exit-nonreturning"
        ):
            raise PlanAuthorityError("WP8C candidate report ABI evidence drifted")
        index += 1
        replay = (ordinal,) + expected[11:] + ("baseline-equal",)
        if index >= len(payload) or tuple(payload[index].split("\t")) != ("replay",) + replay:
            raise PlanAuthorityError("WP8C candidate report replay evidence drifted")
        index += 1

        physical_reads = 0
        physical_writes = 0
        selected_slot = expected[5]
        for block_id in range(int(expected[10])):
            if index >= len(payload):
                raise PlanAuthorityError("WP8C candidate report truncated before block")
            block = payload[index].split("\t")
            if len(block) != 4 or block[:3] != ["block", ordinal, str(block_id)]:
                raise PlanAuthorityError("WP8C candidate report block order drifted")
            if not UINT_RE.fullmatch(block[3]):
                raise PlanAuthorityError("WP8C candidate report instruction count is malformed")
            instruction_count = int(block[3])
            index += 1
            for instruction_id in range(instruction_count):
                if index >= len(payload):
                    raise PlanAuthorityError("WP8C candidate report truncated within block")
                fields = payload[index].split("\t")
                if len(fields) < 6 or fields[:4] != [
                    "instruction",
                    ordinal,
                    str(block_id),
                    str(instruction_id),
                ]:
                    raise PlanAuthorityError("WP8C candidate instruction order drifted")
                opcode = fields[4]
                if opcode == "load-physical":
                    if fields[-1] != "r12":
                        raise PlanAuthorityError("WP8C candidate reads an unbound physical register")
                    physical_reads += 1
                elif opcode == "store-physical":
                    if fields[5] != "r12":
                        raise PlanAuthorityError("WP8C candidate writes an unbound physical register")
                    physical_writes += 1
                elif opcode == "load-slot" and fields[-1] == selected_slot:
                    raise PlanAuthorityError("WP8C selected slot still has a load")
                elif opcode in {"store-slot", "add-slot-const"} and fields[5] == selected_slot:
                    raise PlanAuthorityError("WP8C selected slot still has a write")
                index += 1
            if index >= len(payload):
                raise PlanAuthorityError("WP8C candidate report lacks a terminator")
            terminator = payload[index].split("\t")
            if len(terminator) < 4 or terminator[:3] != ["terminator", ordinal, str(block_id)]:
                raise PlanAuthorityError("WP8C candidate terminator order drifted")
            index += 1
        if (physical_reads, physical_writes) != (int(expected[8]), int(expected[9])):
            raise PlanAuthorityError("WP8C physical access cardinality drifted")
        observed.append(kernel)

    verifications, index = _take(payload, index, "verification", 2)
    if tuple(row[0] for row in verifications) != EXPECTED_VERIFICATIONS or index != len(payload):
        raise PlanAuthorityError("WP8C candidate report verification extent drifted")
    return PlanReport(PLAN_REPORT_SHA256, PLAN_REPORT_ROOT, tuple(observed))


def _admission_report(contract: Contract, authority: Authority, plan: PlanReport) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"candidate-report-root\t{plan.root}",
        f"candidate-report-sha256\t{plan.sha256}",
        "status\tcandidate-plan-semantically-admitted",
        "encoding-status\tforbidden",
        "native-execution-status\tforbidden",
        "measurement-status\tforbidden",
        "claim-status\tnot-admitted",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate_static(root: Path) -> tuple[Contract, Authority]:
    root = root.resolve(strict=True)
    contract = parse_contract(root / "distribution/s4-performance/WP8C-CANDIDATE-PLAN.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP8C-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_parents(root)
    _verify_static_boundary(root)
    return contract, authority


def validate(root: Path, report_path: Path) -> Admission:
    root = root.resolve(strict=True)
    contract, authority = validate_static(root)
    plan = parse_plan_report(report_path.resolve(strict=True), contract)
    report, report_root = _admission_report(contract, authority, plan)
    return Admission(contract, authority, plan, report, report_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        admission = validate(arguments.root, arguments.report)
        sys.stdout.buffer.write(admission.report)
    except (PlanAuthorityError, wp8b.ResidencyError, OSError) as error:
        print(f"WP8C validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
