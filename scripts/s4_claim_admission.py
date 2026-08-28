#!/usr/bin/env python3
"""Validate the blocked, static-only S4-WP7E claim-admission protocol."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_benchmark_authority as wp1
import s4_controlled_host as wp6
import s4_measurement_evidence as wp7a
import s4_measurement_runner as wp7c
import s4_residual_role_admission as wp5f
import s4_threshold_evaluator as wp7d


CONTRACT_MAGIC = "NAUX-S4-CLAIM-ADMISSION-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-CLAIM-ADMISSION-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-CLAIM-ADMISSION-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-claim-admission:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-claim-admission:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-claim-admission:report:v1\0"
WP1_AUTHORITY_SEAL = "b23533c4e96ec9e3b66482e96b79fdeb5985c823ce012d827e69eb1c14a4b659"
WP5F_AUTHORITY_SEAL = "1d85ad923f5db2eb520cee9d3582bbc97f63b711c67d5d4b44d5859fb0fa92bd"
WP6_AUTHORITY_SEAL = "3062a5197fa1fcbe50f60b624b75b2be37c55a0c1193d1eeeffc03e7f03caaf0"
WP7A_AUTHORITY_SEAL = "7e10bc03b30b532f05e67c6f6d3ce80d7430125bcae7b9e3824c86cfc233f0bc"
WP7C_AUTHORITY_SEAL = "7eb774dd2047d249a87806ae8ca1daaef11698fbab3975ac29f458a7b0766571"
WP7D_AUTHORITY_SEAL = "bbf5d09e9f25a8995898d54deaf6ff059579e0d227680c4af9481d1a0c3f7615"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-benchmark-authority", WP1_AUTHORITY_SEAL),
    ("parent-residual-role-authority", WP5F_AUTHORITY_SEAL),
    ("parent-host-protocol-authority", WP6_AUTHORITY_SEAL),
    ("parent-evidence-law-authority", WP7A_AUTHORITY_SEAL),
    ("parent-runner-authority", WP7C_AUTHORITY_SEAL),
    ("parent-threshold-authority", WP7D_AUTHORITY_SEAL),
    ("protocol-status", "claim-protocol-structurally-admitted"),
    ("admission-status", "blocked"),
    ("default-mode", "static-no-host-no-network-no-clock-no-execution"),
    ("claim-status", "not-admitted"),
    ("claim-class", "bounded-kernel-threshold-observation"),
    ("claim-scope", "exact-host-commit-bundle-and-kernels-only"),
    ("target", "x86_64-unknown-linux-gnu"),
)
CONTRACT_CLASSES = (
    ("01", "bounded-kernel-threshold-observation", "permitted-only-after-all-gates"),
    ("02", "language-wide-performance-leadership", "forbidden"),
    ("03", "production-performance", "forbidden"),
    ("04", "unmeasured-workload-extrapolation", "forbidden"),
)
CONTRACT_GATES = (
    ("01", "public-protocol-acceptance", "required", "exact-tracked-commit-and-green-public-ci"),
    ("02", "eligible-host", "required", "exact-retained-wp6-attestation"),
    ("03", "immutable-bundle", "required", "exact-public-wp7c-root-and-inventory"),
    ("04", "evidence", "required", "exact-wp7a-replay-and-all-variance-pass"),
    ("05", "threshold", "required", "exact-wp7d-same-kernel-candidate-pass"),
    ("06", "claim-text", "required", "exact-host-commit-bundle-kernel-qualified"),
    ("07", "release-approval", "required", "distinct-explicit-owner-approval"),
    ("08", "non-self-admission", "required", "checker-cannot-grant-claim-authority"),
)
CONTRACT_BLOCKERS = (
    ("01", "tracked-public-protocol-acceptance-unavailable"),
    ("02", "eligible-controlled-bundle-unavailable"),
    ("03", "exact-public-claim-request-unavailable"),
    ("04", "distinct-release-approval-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP7E"),
    ("authority-id", "s4-performance-claim-admission-v1"),
    ("protocol-status", "claim-protocol-structurally-admitted"),
    ("admission-status", "blocked"),
    ("claim-status", "not-admitted"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-claim-admission.yml",
    "distribution/s4-performance/WP7E-CLAIM.tsv",
    "distribution/s4-performance/WP7E-NONCLAIMS.md",
    "distribution/s4-performance/WP7E-README.md",
    "scripts/s4_claim_admission.py",
    "scripts/tests/test_s4_claim_admission_refusal.py",
    "scripts/tests/test_s4_claim_admission_static.py",
)


class ClaimAdmissionError(RuntimeError):
    """A fail-closed S4-WP7E protocol error."""


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


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(raw: bytes, label: str, maximum: int = 2_000_000) -> list[str]:
    if not raw or len(raw) > maximum or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise ClaimAdmissionError(f"{label} has invalid extent or encoding")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ClaimAdmissionError(f"{label} is not UTF-8") from error
    lines = text.splitlines()
    if any(not line for line in lines):
        raise ClaimAdmissionError(f"{label} contains a blank row")
    return lines


def _regular(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise ClaimAdmissionError(f"cannot read {label}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ClaimAdmissionError(f"{label} is not a regular file")
    if len(raw) > 2_000_000:
        raise ClaimAdmissionError(f"{label} exceeds its extent limit")
    return raw


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    lines = _canonical(_regular(path, path.name), path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise ClaimAdmissionError(f"{path.name} magic or shape drifted")
    if any(line.startswith("seal\t") for line in lines[:-1]):
        raise ClaimAdmissionError(f"{path.name} contains a non-terminal seal")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise ClaimAdmissionError(f"{path.name} seal row is malformed")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if _sha256(domain + body) != fields[1]:
        raise ClaimAdmissionError(f"{path.name} seal mismatch")
    return lines[1:-1], fields[1]


def _take(lines: list[str], index: int, tag: str, width: int) -> tuple[list[tuple[str, ...]], int]:
    rows: list[tuple[str, ...]] = []
    while index < len(lines) and lines[index].startswith(f"{tag}\t"):
        fields = lines[index].split("\t")
        if len(fields) != width:
            raise ClaimAdmissionError(f"WP7E {tag} row is malformed")
        rows.append(tuple(fields[1:]))
        index += 1
    return rows, index


def _safe_relative(value: str) -> None:
    if not PATH_RE.fullmatch(value):
        raise ClaimAdmissionError("path token is malformed")
    path = Path(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise ClaimAdmissionError("path is absolute or traversing")


def parse_contract(path: Path) -> Contract:
    lines, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    index = 0
    metadata, index = _take(lines, index, "meta", 3)
    classes, index = _take(lines, index, "class", 4)
    gates, index = _take(lines, index, "gate", 5)
    blockers, index = _take(lines, index, "blocker", 3)
    if tuple(metadata) != CONTRACT_METADATA:
        raise ClaimAdmissionError("WP7E contract metadata drifted")
    if tuple(classes) != CONTRACT_CLASSES or tuple(gates) != CONTRACT_GATES:
        raise ClaimAdmissionError("WP7E claim class or gate set drifted")
    if tuple(blockers) != CONTRACT_BLOCKERS or index != len(lines):
        raise ClaimAdmissionError("WP7E blocker set or extent drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    index = 0
    metadata, index = _take(lines, index, "meta", 3)
    if tuple(metadata) != AUTHORITY_METADATA:
        raise ClaimAdmissionError("WP7E authority metadata drifted")
    expected_links = (
        ("component", "claim-contract", "distribution/s4-performance/WP7E-CLAIM.tsv", contract_seal),
        ("parent", "benchmark-authority", "distribution/s4-performance/AUTHORITY.tsv", WP1_AUTHORITY_SEAL),
        ("parent", "residual-role-authority", "distribution/s4-performance/WP5F-AUTHORITY.tsv", WP5F_AUTHORITY_SEAL),
        ("parent", "host-protocol-authority", "distribution/s4-performance/WP6-AUTHORITY.tsv", WP6_AUTHORITY_SEAL),
        ("parent", "evidence-law-authority", "distribution/s4-performance/WP7A-AUTHORITY.tsv", WP7A_AUTHORITY_SEAL),
        ("parent", "runner-authority", "distribution/s4-performance/WP7C-AUTHORITY.tsv", WP7C_AUTHORITY_SEAL),
        ("parent", "threshold-authority", "distribution/s4-performance/WP7D-AUTHORITY.tsv", WP7D_AUTHORITY_SEAL),
    )
    links: list[tuple[str, ...]] = []
    for _expected in expected_links:
        if index >= len(lines):
            raise ClaimAdmissionError("WP7E authority binding is missing")
        links.append(tuple(lines[index].split("\t")))
        index += 1
    if tuple(links) != expected_links:
        raise ClaimAdmissionError("WP7E authority binding drifted")
    files: list[FileRecord] = []
    while index < len(lines):
        fields = lines[index].split("\t")
        if (
            len(fields) != 6
            or fields[0] != "file"
            or not MODE_RE.fullmatch(fields[1])
            or not UINT_RE.fullmatch(fields[2])
            or int(fields[2]) > 2_000_000
            or not HASH_RE.fullmatch(fields[3])
            or fields[5] != "claim-admission"
        ):
            raise ClaimAdmissionError("WP7E authority file row is malformed")
        _safe_relative(fields[4])
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
        index += 1
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise ClaimAdmissionError("WP7E authority file inventory drifted")
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        raw = _regular(path, record.path)
        metadata = path.lstat()
        mode = stat.S_IFREG | stat.S_IMODE(metadata.st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise ClaimAdmissionError(f"WP7E bound file identity drifted: {record.path}")


def _verify_static_boundary(root: Path) -> None:
    workflow = (root / ".github/workflows/s4-claim-admission.yml").read_text()
    for token in (
        "scripts/s4_claim_admission.py",
        "test_s4_claim_admission_static",
        "test_s4_claim_admission_refusal",
    ):
        if token not in workflow:
            raise ClaimAdmissionError("WP7E workflow omits a static gate")
    source = "\n".join((root / relative).read_text() for relative in EXPECTED_FILES)
    forbidden = (
        "--" + "bundle",
        "--" + "candidate",
        "--" + "request",
        "--" + "admit",
        "import " + "time",
        "import " + "subprocess",
        "import " + "resource",
        "import " + "socket",
        "import " + "urllib",
        "os." + "fork(",
        "os." + "execve(",
    )
    if any(token in source for token in forbidden):
        raise ClaimAdmissionError("WP7E exposes acquisition or admission capability")
    expected = {"WP7E-AUTHORITY.tsv", "WP7E-CLAIM.tsv", "WP7E-NONCLAIMS.md", "WP7E-README.md"}
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP7E-*")
        if path.is_file()
    }
    if actual != expected:
        raise ClaimAdmissionError("unexpected WP7E distribution artifact")


def _static_report(contract: Contract, authority: Authority) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"parent-benchmark-authority\t{WP1_AUTHORITY_SEAL}",
        f"parent-residual-role-authority\t{WP5F_AUTHORITY_SEAL}",
        f"parent-host-protocol-authority\t{WP6_AUTHORITY_SEAL}",
        f"parent-evidence-law-authority\t{WP7A_AUTHORITY_SEAL}",
        f"parent-runner-authority\t{WP7C_AUTHORITY_SEAL}",
        f"parent-threshold-authority\t{WP7D_AUTHORITY_SEAL}",
        "protocol-status\tclaim-protocol-structurally-admitted",
        "admission-status\tblocked",
        "mode\tstatic-no-host-no-network-no-clock-no-execution",
        "claim-status\tnot-admitted",
        "blockers\t4",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve()
    parents = (
        (wp1.validate(root).authority.seal, WP1_AUTHORITY_SEAL, "WP1"),
        (wp5f.validate(root).authority.seal, WP5F_AUTHORITY_SEAL, "WP5F"),
        (wp6.validate(root).authority.seal, WP6_AUTHORITY_SEAL, "WP6"),
        (wp7a.validate(root).authority.seal, WP7A_AUTHORITY_SEAL, "WP7A"),
        (wp7c.validate(root).authority.seal, WP7C_AUTHORITY_SEAL, "WP7C"),
        (wp7d.validate(root).authority.seal, WP7D_AUTHORITY_SEAL, "WP7D"),
    )
    for observed, expected, label in parents:
        if observed != expected:
            raise ClaimAdmissionError(f"accepted {label} authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP7E-CLAIM.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP7E-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_static_boundary(root)
    report, report_root = _static_report(contract, authority)
    return Admission(contract, authority, report, report_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args(argv)
    try:
        sys.stdout.buffer.write(validate(arguments.root).report)
        return 0
    except (
        ClaimAdmissionError,
        wp1.BenchmarkAuthorityError,
        wp5f.RoleAdmissionError,
        wp6.HostControlError,
        wp7a.EvidenceError,
        wp7c.RunnerError,
        wp7d.ThresholdError,
        OSError,
        ValueError,
    ) as error:
        print(f"S4-WP7E validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
