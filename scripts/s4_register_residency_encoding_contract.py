#!/usr/bin/env python3
"""Validate the contract-only S4-WP8D register-residency encoding boundary."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_plan_authority as wp8c
import s4_residual_elf64 as wp5d


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-ENCODING-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-ENCODING-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-ENCODING-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-encoding-contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-encoding-authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-encoding-report:v1\0"
CONTRACT_SEAL = "96179672d0bdce3784ce30d2aa2760d71964725352c0769839750ba78e12a5f8"
WP8C_CONTRACT_SEAL = "2669d74517889dc65ec25562e501d9ddb07da298966cc75644e8b20cd4bf0d47"
WP8C_AUTHORITY_SEAL = "65b47c8591c17c8b5b881a127effa515dc9237822a6547cf419193ce72aa16f9"
WP8C_PLAN_REPORT_ROOT = "87e41ae9c0752ffe7738c8ea76e4df4d56751fc3a89f78cef8ece9e79083438e"
WP8C_ADMISSION_ROOT = "b93e50b33af7f9e030208cca398e1bc35f9ca885e64c91cf043e2539ce9a967e"
WP5D_CONTRACT_SEAL = "4219b6842f92d659daa4ed5bc144ae312710010d7f763b0e27bfd4ba3957518c"
WP5D_SOURCE_SHA256 = "1424d65d5c108095b9179b1af7280c688d64dfd5006d1249c7ef6286e5a36a0f"
MAX_FILE_BYTES = 1_000_000
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-wp8c-contract", WP8C_CONTRACT_SEAL),
    ("parent-wp8c-authority", WP8C_AUTHORITY_SEAL),
    ("parent-wp8c-plan-report-root", WP8C_PLAN_REPORT_ROOT),
    ("parent-wp8c-admission-root", WP8C_ADMISSION_ROOT),
    ("frozen-wp5d-contract", WP5D_CONTRACT_SEAL),
    ("frozen-wp5d-source-sha256", WP5D_SOURCE_SHA256),
    ("transform-id", "one-hot-loop-index-r12-v1"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("status", "encoding-contract-admitted"),
    ("implementation-status", "absent"),
    ("candidate-bytes-status", "absent"),
    ("native-execution-status", "forbidden"),
    ("measurement-status", "forbidden"),
    ("claim-status", "not-admitted"),
    ("encoding-model", "symbolic-width-and-placement-v1"),
    ("callee-save-home", "promoted-slot-abi-shadow"),
    ("frame-policy", "exact-wp5d-frame-bytes"),
    ("cfg-policy", "exact-wp8c-blocks-and-terminators"),
    ("rollback-policy", "exact-wp5d-target"),
    ("kernel-count", "4"),
)
CONTRACT_GATES = (
    ("01", "parent-chain", "required", "exact-wp8c-contract-authority-and-report-roots"),
    ("02", "baseline-chain", "required", "exact-wp5d-contract-source-and-target-identities"),
    ("03", "encoding-surface", "required", "exact-four-symbolic-templates-only"),
    ("04", "callee-save", "required", "r12-saved-in-promoted-slot-before-entry-block"),
    ("05", "callee-restore", "required", "r12-restored-on-every-return"),
    ("06", "error-path", "required", "nonreturning-error-suffix-never-restores-or-rejoins"),
    ("07", "frame", "required", "exact-wp5d-frame-immediate-and-home-layout"),
    ("08", "control-flow", "required", "exact-wp8c-block-terminator-and-fixup-target-shape"),
    ("09", "passthrough", "required", "all-unselected-operations-use-frozen-wp5d-lowering"),
    ("10", "transformed-sites", "required", "exact-wp8c-read-and-write-sites-only"),
    ("11", "byte-budget", "required", "exact-symbolic-width-accounting-and-strict-decrease"),
    ("12", "rollback", "required", "any-failed-gate-retains-exact-wp5d-target"),
    ("13", "quarantine", "required", "no-candidate-byte-artifact-execution-or-measurement"),
    ("14", "claim-boundary", "required", "not-admitted"),
)
EXPECTED_TEMPLATES = (
    ("01", "abi-save", "caller-r12-to-promoted-shadow", "mov-rm64-r64", "rbp-disp32", "7", "once-after-frame-allocation"),
    ("02", "load-physical", "r12-to-result-home", "mov-rm64-r64", "rbp-disp32", "7", "exact-wp8c-read-sites"),
    ("03", "store-physical", "value-home-to-r12", "mov-r64-rm64", "rbp-disp32", "7", "exact-wp8c-write-sites"),
    ("04", "abi-restore", "promoted-shadow-to-caller-r12", "mov-r64-rm64", "rbp-disp32", "7", "once-before-each-return"),
)
EXPECTED_KERNELS = (
    ("01", "sum-dense", "97d8699e9449d53f4f3c9386839099be194b7db985709122092dfac3eacb8f2d", "98e3ac1191dbb078730f024f12a8f4b310f542bfed72830b32cfce127b705e27", "6e20cd38880cecb4a37532735d9c1cad84dc6b79eec5432b6fbf0a7fd62d2df8", "288", "s5", "-48", "3", "2", "5", "70", "35", "7", "7", "1", "993", "972", "21", "979", "958"),
    ("02", "branch-mix", "8095c962d36b2a6876770412feac0df8fdd5f4e3627481f97f6b78f9bc489888", "68ef1e141aac58454b2b1dde0bcf8d2ea100c4faa1ee43323ce121b6471a86ad", "ab9b853e71b7ac1675446affa9d02e16f514bb0bbb9ca688f3d3361981da620d", "352", "s6", "-56", "3", "2", "5", "70", "35", "7", "7", "1", "1188", "1167", "21", "1174", "1153"),
    ("03", "dot-product", "b2fa698b60cb29e50d14e7f56650d1f09657562e3160e99bc7930e60f7c9e857", "c3a3bb75473b90689646c413552de32005ea27594d0565b72cc1984c731b7a3b", "b11082e8f079692a34559ba979dfd95e29da232ffbc85ad543b37d44e2a3271d", "288", "s5", "-48", "3", "2", "5", "70", "35", "7", "7", "1", "950", "929", "21", "936", "915"),
    ("04", "list-update", "c6ac1a97cad0ec0529e7f5f49bb91d316fa63a2b9abb2c7452a0040fe4150199", "de4e36706adc23c47bae3c95d0b45719867684423897b59b462e0cd937c6f982", "b7ba7ad25cf0209c355074130032c3b37adc8fe35cae4a926b4c5ff8103ad336", "336", "s5", "-48", "4", "2", "6", "84", "42", "7", "7", "1", "1071", "1043", "28", "1057", "1029"),
)
EXPECTED_VERIFICATIONS = (
    "no-candidate-byte-payload",
    "exact-width-equation-per-kernel",
    "promoted-slot-is-caller-r12-shadow-only",
    "unchanged-frame-cfg-error-suffix-and-rollback",
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8D"),
    ("authority-id", "s4-one-hot-loop-index-r12-encoding-contract-v1"),
    ("status", "encoding-contract-admitted"),
    ("implementation-status", "absent"),
    ("candidate-bytes-status", "absent"),
    ("native-execution-status", "forbidden"),
    ("measurement-status", "forbidden"),
    ("claim-status", "not-admitted"),
    ("file-count", "6"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-encoding-contract.yml",
    "distribution/s4-performance/WP8D-ENCODING-CONTRACT.tsv",
    "distribution/s4-performance/WP8D-NONCLAIMS.md",
    "distribution/s4-performance/WP8D-README.md",
    "scripts/s4_register_residency_encoding_contract.py",
    "scripts/tests/test_s4_register_residency_encoding_contract.py",
)


class EncodingContractError(RuntimeError):
    """A fail-closed WP8D encoding-contract error."""


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


def _read_regular(path: Path, label: str) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise EncodingContractError(f"{label} is not regular")
    if before.st_size > MAX_FILE_BYTES:
        raise EncodingContractError(f"{label} exceeds the bounded input limit")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise EncodingContractError(f"{label} changed before open")
        raw = handle.read(MAX_FILE_BYTES + 1)
        after = os.fstat(handle.fileno())
    rebound = path.lstat()
    if (opened.st_dev, opened.st_ino, opened.st_size) != (after.st_dev, after.st_ino, after.st_size) or len(raw) != after.st_size:
        raise EncodingContractError(f"{label} changed while read")
    if stat.S_ISLNK(rebound.st_mode) or not stat.S_ISREG(rebound.st_mode) or (after.st_dev, after.st_ino) != (rebound.st_dev, rebound.st_ino):
        raise EncodingContractError(f"{label} pathname changed while read")
    if len(raw) > MAX_FILE_BYTES:
        raise EncodingContractError(f"{label} exceeds the bounded input limit")
    return raw


def _canonical(raw: bytes, label: str) -> list[str]:
    if not raw or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise EncodingContractError(f"{label} has invalid extent or encoding")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise EncodingContractError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise EncodingContractError(f"{label} contains blank or padded rows")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    lines = _canonical(_read_regular(path, path.name), path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise EncodingContractError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]) or _sha256(domain + body) != fields[1]:
        raise EncodingContractError(f"{path.name} seal mismatch")
    return lines[1:-1], fields[1]


def _take(lines: list[str], index: int, tag: str, width: int) -> tuple[list[tuple[str, ...]], int]:
    rows: list[tuple[str, ...]] = []
    while index < len(lines) and lines[index].startswith(f"{tag}\t"):
        fields = lines[index].split("\t")
        if len(fields) != width:
            raise EncodingContractError(f"malformed WP8D {tag} row")
        rows.append(tuple(fields[1:]))
        index += 1
    return rows, index


def parse_contract(path: Path) -> Contract:
    lines, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    metadata, index = _take(lines, 0, "meta", 3)
    gates, index = _take(lines, index, "gate", 5)
    templates, index = _take(lines, index, "template", 8)
    kernels, index = _take(lines, index, "kernel", 22)
    verifications, index = _take(lines, index, "verification", 2)
    if tuple(metadata) != CONTRACT_METADATA or tuple(gates) != CONTRACT_GATES:
        raise EncodingContractError("WP8D metadata or gates drifted")
    if tuple(templates) != EXPECTED_TEMPLATES or tuple(kernels) != EXPECTED_KERNELS:
        raise EncodingContractError("WP8D templates or kernel budgets drifted")
    if tuple(row[0] for row in verifications) != EXPECTED_VERIFICATIONS or index != len(lines):
        raise EncodingContractError("WP8D verification surface drifted")
    if seal != CONTRACT_SEAL:
        raise EncodingContractError("WP8D accepted contract identity drifted")
    return Contract(tuple(kernels), seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    metadata, index = _take(lines, 0, "meta", 3)
    if tuple(metadata) != AUTHORITY_METADATA:
        raise EncodingContractError("WP8D authority metadata drifted")
    links = (
        f"component\tencoding-contract\tdistribution/s4-performance/WP8D-ENCODING-CONTRACT.tsv\t{contract_seal}",
        f"parent\twp8c-contract\tdistribution/s4-performance/WP8C-CANDIDATE-PLAN.tsv\t{WP8C_CONTRACT_SEAL}",
        f"parent\twp8c-authority\tdistribution/s4-performance/WP8C-AUTHORITY.tsv\t{WP8C_AUTHORITY_SEAL}",
        f"parent\twp5d-contract\tdistribution/s4-performance/WP5D-ELF64.tsv\t{WP5D_CONTRACT_SEAL}",
    )
    if tuple(lines[index : index + len(links)]) != links:
        raise EncodingContractError("WP8D component or parent binding drifted")
    index += len(links)
    files: list[FileRecord] = []
    while index < len(lines):
        fields = lines[index].split("\t")
        if len(fields) != 6 or fields[0] != "file" or not MODE_RE.fullmatch(fields[1]) or not UINT_RE.fullmatch(fields[2]) or not HASH_RE.fullmatch(fields[3]) or fields[4] not in EXPECTED_FILES or fields[5] != "register-residency-encoding-contract":
            raise EncodingContractError("WP8D authority file row is malformed")
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
        index += 1
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise EncodingContractError("WP8D authority inventory drifted")
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        raw = _read_regular(path, record.path)
        metadata = path.lstat()
        if stat.S_IMODE(metadata.st_mode) != record.mode & 0o777 or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise EncodingContractError(f"bound WP8D file drifted: {record.path}")


def _wp8c_admission_root(contract: wp8c.Contract, authority: wp8c.Authority) -> str:
    rows = (
        wp8c.REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"candidate-report-root\t{wp8c.PLAN_REPORT_ROOT}",
        f"candidate-report-sha256\t{wp8c.PLAN_REPORT_SHA256}",
        "status\tcandidate-plan-semantically-admitted",
        "encoding-status\tforbidden",
        "native-execution-status\tforbidden",
        "measurement-status\tforbidden",
        "claim-status\tnot-admitted",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    return _sha256(wp8c.REPORT_DOMAIN + body)


def _verify_parents(root: Path, contract: Contract) -> None:
    parent_contract, parent_authority = wp8c.validate_static(root)
    if parent_contract.seal != WP8C_CONTRACT_SEAL or parent_authority.seal != WP8C_AUTHORITY_SEAL:
        raise EncodingContractError("WP8D WP8C parent drifted")
    if _wp8c_admission_root(parent_contract, parent_authority) != WP8C_ADMISSION_ROOT:
        raise EncodingContractError("WP8D WP8C admission identity drifted")
    baseline = wp5d.parse_contract(root / "distribution/s4-performance/WP5D-ELF64.tsv")
    if baseline.seal != WP5D_CONTRACT_SEAL:
        raise EncodingContractError("WP8D WP5D contract drifted")
    source = _read_regular(root / "naux-lang/examples/support/s4_residual_x64_elf.rs", "WP5D lowering source")
    if _sha256(source) != WP5D_SOURCE_SHA256:
        raise EncodingContractError("WP8D WP5D source drifted")

    for encoded, planned, frozen in zip(contract.kernels, parent_contract.kernels, baseline.records, strict=True):
        if encoded[:4] != planned[:4] or encoded[4] != frozen.target_hash:
            raise EncodingContractError("WP8D parent kernel identity drifted")
        if encoded[5] != planned[4] or encoded[5] != str(frozen.frame_bytes) or encoded[6] != planned[5]:
            raise EncodingContractError("WP8D frame or promoted home drifted")
        reads, writes = int(encoded[8]), int(encoded[9])
        sites = int(encoded[10])
        baseline_sites, candidate_sites = int(encoded[11]), int(encoded[12])
        save, restore, returns = int(encoded[13]), int(encoded[14]), int(encoded[15])
        baseline_bytes, candidate_bytes, decrease = int(encoded[16]), int(encoded[17]), int(encoded[18])
        baseline_error, candidate_error = int(encoded[19]), int(encoded[20])
        expected_displacement = -8 * (int(encoded[6][1:]) + 1)
        if encoded[7] != str(expected_displacement) or (reads, writes) != (int(planned[8]), int(planned[9])):
            raise EncodingContractError("WP8D access home or cardinality drifted")
        if sites != reads + writes or baseline_sites != sites * 14 or candidate_sites != sites * 7:
            raise EncodingContractError("WP8D transformed-site width equation drifted")
        expected_candidate = baseline_bytes - baseline_sites + candidate_sites + save + restore * returns
        if baseline_bytes != frozen.target_bytes or baseline_error != frozen.error_offset or candidate_bytes != expected_candidate:
            raise EncodingContractError("WP8D target-byte equation drifted")
        if decrease != baseline_bytes - candidate_bytes or decrease <= 0 or candidate_error != baseline_error - decrease:
            raise EncodingContractError("WP8D strict decrease or error-offset equation drifted")
        if (save, restore, returns) != (7, 7, 1):
            raise EncodingContractError("WP8D ABI template cardinality drifted")


def _verify_static_boundary(root: Path, authority: Authority) -> None:
    source = _read_regular(root / "scripts/s4_register_residency_encoding_contract.py", "WP8D validator source").decode()
    forbidden = ("sub" + "process", "time." + "time(", "perf_" + "counter(", "sock" + "et", "requ" + "ests", "url" + "lib", "cty" + "pes")
    if any(token in source for token in forbidden):
        raise EncodingContractError("WP8D validator crossed its static boundary")
    if any(path.endswith((".bin", ".elf", ".o", ".so", ".exe")) for path in (record.path for record in authority.files)):
        raise EncodingContractError("WP8D authority binds a candidate byte artifact")


def _report(contract: Contract, authority: Authority) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"parent-wp8c-authority\t{WP8C_AUTHORITY_SEAL}",
        "status\tencoding-contract-admitted",
        "implementation-status\tabsent",
        "candidate-bytes-status\tabsent",
        "native-execution-status\tforbidden",
        "measurement-status\tforbidden",
        "claim-status\tnot-admitted",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    contract = parse_contract(root / "distribution/s4-performance/WP8D-ENCODING-CONTRACT.tsv")
    authority = parse_authority(root / "distribution/s4-performance/WP8D-AUTHORITY.tsv", contract.seal)
    _verify_files(root, authority)
    _verify_parents(root, contract)
    _verify_static_boundary(root, authority)
    report, report_root = _report(contract, authority)
    return Admission(contract, authority, report, report_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args(argv)
    try:
        admission = validate(arguments.root)
        sys.stdout.buffer.write(admission.report)
    except (EncodingContractError, wp8c.PlanAuthorityError, wp8c.wp8b.ResidencyError, wp5d.Elf64Error, OSError, ValueError) as error:
        print(f"WP8D validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
