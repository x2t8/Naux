#!/usr/bin/env python3
"""Validate the contract-only S4-WP8B register-residency boundary."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import license_transition as lt1
import s4_performance_gap_forensics as wp8a
import s4_residual_elf64 as wp5d
import s4_residual_machine_ir as wp5c


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency:report:v1\0"
WP8A_CONTRACT_SEAL = "eb0c7a1fa087b942e102906514674c8d74e41137749da31e55be3b2aee6cb8c6"
WP8A_AUTHORITY_SEAL = "6ba069fa75e8dfc49e60794c76097434868013fe38afc1c3c937fe7f818dae16"
LT1_CONTRACT_SEAL = "10589dc5e6e594e76d25a45d09924aed456ef7b05aa94d95572dcf14b7be4c6d"
LT1_AUTHORITY_SEAL = "e22888ecc999dcaeb4ba33aea4eaf713b251750cf5f1ac278dd5c1c1b4c9485e"
SOURCE_COMMIT = "7d270a54c0af7530585fde7be4d9f3f67c15e142"
BUNDLE_ROOT = "3b28e2d8c1c73af037c7455a5e81bf788d3301620c53979bb7f2d5c3d6e95e6b"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
MAX_FILE_BYTES = 1_000_000

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-wp8a-contract", WP8A_CONTRACT_SEAL),
    ("parent-wp8a-authority", WP8A_AUTHORITY_SEAL),
    ("parent-lt1-contract", LT1_CONTRACT_SEAL),
    ("parent-lt1-authority", LT1_AUTHORITY_SEAL),
    ("baseline-source-commit", SOURCE_COMMIT),
    ("baseline-bundle-root", BUNDLE_ROOT),
    ("baseline-threshold-candidate", "fail"),
    ("candidate", "register-resident-hot-state"),
    ("candidate-rank", "1"),
    ("candidate-structural-exposure", "145291757"),
    ("transform-id", "one-hot-loop-index-r12-v1"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("input-target-plan", "stack-home-x86-64-v1"),
    ("output-target-plan", "one-hot-slot-r12-x86-64-v1"),
    ("physical-register", "r12"),
    ("register-class", "callee-saved-gpr"),
    ("promotion-count-per-kernel", "1"),
    ("selected-structural-exposure", "13926800"),
    ("kernel-count", "4"),
    ("clock-policy", "forbidden"),
    ("native-execution-policy", "forbidden-until-transform-admission"),
    ("remeasurement-policy", "forbidden-until-new-eligibility"),
    ("claim-status", "not-admitted"),
)
CONTRACT_GATES = (
    ("01", "parent-chain", "required", "exact-wp8a-and-lt1-seals"),
    ("02", "candidate-selection", "required", "exact-rank-one-structural-class"),
    ("03", "promotion-cardinality", "required", "exactly-one-i64-slot-per-kernel"),
    ("04", "loop-carried-proof", "required", "exact-inner-index-read-write-sites"),
    ("05", "abi-preservation", "required", "r12-save-on-entry-restore-on-return"),
    ("06", "error-path", "required", "nonreturning-exit-never-rejoins-caller"),
    ("07", "frame-budget", "required", "frame-bytes-must-not-increase"),
    ("08", "code-size-budget", "required", "target-bytes-strictly-decrease"),
    ("09", "semantic-proof", "required", "plan-differential-oracle-owner-and-overflow"),
    ("10", "rollback", "required", "any-failed-gate-retains-stack-home-target"),
    ("11", "measurement-quarantine", "required", "no-wp7c-replacement-or-remeasurement"),
    ("12", "claim-boundary", "required", "not-admitted"),
)
EXPECTED_KERNELS = (
    ("01", "sum-dense", "97d8699e9449d53f4f3c9386839099be194b7db985709122092dfac3eacb8f2d", "s5", "i64", "r12", "2457650", "819250", "3276900", "993", "992"),
    ("02", "branch-mix", "8095c962d36b2a6876770412feac0df8fdd5f4e3627481f97f6b78f9bc489888", "s6", "i64", "r12", "2457650", "819250", "3276900", "1188", "1187"),
    ("03", "dot-product", "b2fa698b60cb29e50d14e7f56650d1f09657562e3160e99bc7930e60f7c9e857", "s5", "i64", "r12", "2457650", "819250", "3276900", "950", "949"),
    ("04", "list-update", "c6ac1a97cad0ec0529e7f5f49bb91d316fa63a2b9abb2c7452a0040fe4150199", "s5", "i64", "r12", "3276850", "819250", "4096100", "1071", "1070"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8B"),
    ("authority-id", "s4-one-hot-loop-index-r12-contract-v1"),
    ("status", "transform-contract-admitted"),
    ("implementation-status", "absent"),
    ("measurement-status", "forbidden"),
    ("claim-status", "not-admitted"),
    ("file-count", "6"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-contract.yml",
    "distribution/s4-performance/WP8B-NONCLAIMS.md",
    "distribution/s4-performance/WP8B-README.md",
    "distribution/s4-performance/WP8B-REGISTER-RESIDENCY.tsv",
    "scripts/s4_register_residency_contract.py",
    "scripts/tests/test_s4_register_residency_contract.py",
)


class ResidencyError(RuntimeError):
    """A fail-closed WP8B contract error."""


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
class Admission:
    contract: Contract
    authority: Authority
    report: bytes
    report_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(raw: bytes, label: str) -> list[str]:
    if not raw or len(raw) > MAX_FILE_BYTES or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise ResidencyError(f"{label} has invalid extent or encoding")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ResidencyError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise ResidencyError(f"{label} contains blank or padded rows")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ResidencyError(f"{path.name} is not regular")
    lines = _canonical(path.read_bytes(), path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise ResidencyError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]) or _sha256(domain + body) != fields[1]:
        raise ResidencyError(f"{path.name} seal mismatch")
    return lines[1:-1], fields[1]


def _take(lines: list[str], index: int, tag: str, width: int) -> tuple[list[tuple[str, ...]], int]:
    rows: list[tuple[str, ...]] = []
    while index < len(lines) and lines[index].startswith(f"{tag}\t"):
        fields = lines[index].split("\t")
        if len(fields) != width:
            raise ResidencyError(f"malformed WP8B {tag} row")
        rows.append(tuple(fields[1:]))
        index += 1
    return rows, index


def parse_contract(path: Path) -> Contract:
    lines, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    metadata, index = _take(lines, 0, "meta", 3)
    gates, index = _take(lines, index, "gate", 5)
    kernels, index = _take(lines, index, "kernel", 12)
    if tuple(metadata) != CONTRACT_METADATA or tuple(gates) != CONTRACT_GATES:
        raise ResidencyError("WP8B metadata or gates drifted")
    if tuple(kernels) != EXPECTED_KERNELS or index != len(lines):
        raise ResidencyError("WP8B kernel selection or extent drifted")
    if sum(int(row[8]) for row in kernels) != 13_926_800:
        raise ResidencyError("WP8B selected structural exposure drifted")
    return Contract(tuple(kernels), seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    metadata, index = _take(lines, 0, "meta", 3)
    if tuple(metadata) != AUTHORITY_METADATA:
        raise ResidencyError("WP8B authority metadata drifted")
    links = (
        f"component\tregister-residency-contract\tdistribution/s4-performance/WP8B-REGISTER-RESIDENCY.tsv\t{contract_seal}",
        f"parent\twp8a-authority\tdistribution/s4-performance/WP8A-AUTHORITY.tsv\t{WP8A_AUTHORITY_SEAL}",
        f"parent\tlt1-authority\tdistribution/license-transition/LT1-AUTHORITY.tsv\t{LT1_AUTHORITY_SEAL}",
    )
    if tuple(lines[index:index + len(links)]) != links:
        raise ResidencyError("WP8B component or parent binding drifted")
    index += len(links)
    files: list[FileRecord] = []
    while index < len(lines):
        fields = lines[index].split("\t")
        if len(fields) != 6 or fields[0] != "file" or not MODE_RE.fullmatch(fields[1]) or not UINT_RE.fullmatch(fields[2]) or not HASH_RE.fullmatch(fields[3]) or fields[4] not in EXPECTED_FILES or fields[5] != "register-residency-contract":
            raise ResidencyError("WP8B authority file row is malformed")
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
        index += 1
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise ResidencyError("WP8B authority inventory drifted")
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        metadata = path.lstat()
        raw = path.read_bytes()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != record.mode & 0o777 or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise ResidencyError(f"bound WP8B file drifted: {record.path}")


def _verify_parents(root: Path, contract: Contract) -> None:
    transition = lt1.validate(root)
    if transition.contract.seal != LT1_CONTRACT_SEAL or transition.authority.seal != LT1_AUTHORITY_SEAL:
        raise ResidencyError("WP8B LT1 parent drifted")
    parent_contract = wp8a.parse_contract(root / "distribution/s4-performance/WP8A-FORENSICS.tsv")
    parent_authority = wp8a.parse_authority(root / "distribution/s4-performance/WP8A-AUTHORITY.tsv", parent_contract.seal)
    if parent_contract.seal != WP8A_CONTRACT_SEAL or parent_authority.seal != WP8A_AUTHORITY_SEAL:
        raise ResidencyError("WP8B WP8A parent drifted")
    machine = wp5c.parse_contract(root / "distribution/s4-performance/WP5C-MACHINE-IR.tsv")
    target = wp5d.parse_contract(root / "distribution/s4-performance/WP5D-ELF64.tsv")
    for selected, machine_record, target_record in zip(contract.kernels, machine.records, target.records, strict=True):
        if selected[0] != f"{machine_record.ordinal:02}" or selected[1] != machine_record.name or selected[2] != machine_record.machine_hash or selected[9] != str(target_record.target_bytes) or int(selected[10]) >= target_record.target_bytes:
            raise ResidencyError("WP8B selected kernel no longer matches WP5C/WP5D")


def _verify_static_boundary(root: Path) -> None:
    source = (root / "scripts/s4_register_residency_contract.py").read_text()
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
        raise ResidencyError("WP8B contract validator crossed its static boundary")


def _report(contract: Contract, authority: Authority) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        "status\ttransform-contract-admitted",
        "implementation-status\tabsent",
        "selected-transform\tone-hot-loop-index-r12-v1",
        "selected-structural-exposure\t13926800",
        "target-byte-status\tunchanged",
        "measurement-status\tforbidden",
        "claim-status\tnot-admitted",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    contract = parse_contract(root / "distribution/s4-performance/WP8B-REGISTER-RESIDENCY.tsv")
    authority = parse_authority(root / "distribution/s4-performance/WP8B-AUTHORITY.tsv", contract.seal)
    _verify_files(root, authority)
    _verify_parents(root, contract)
    _verify_static_boundary(root)
    report, report_root = _report(contract, authority)
    return Admission(contract, authority, report, report_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args(argv)
    try:
        admission = validate(arguments.root)
        sys.stdout.buffer.write(admission.report)
    except (ResidencyError, lt1.TransitionError, wp8a.ForensicsError, wp5c.MachineIrError, wp5d.Elf64Error, OSError) as error:
        print(f"WP8B validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
