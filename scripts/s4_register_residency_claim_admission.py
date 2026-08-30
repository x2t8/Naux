#!/usr/bin/env python3
"""Validate the blocked, static-only S4-WP8P claim boundary."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_paired_threshold as wp8o


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-CLAIM-ADMISSION-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-CLAIM-ADMISSION-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-CLAIM-ADMISSION-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-claim-admission:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-claim-admission:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-claim-admission:report:v1\0"
CONTRACT_SEAL = "cd2913e9d388dff4a36eca525c6884280c8e9a60b7956f43e63eb7dd00e6ef2f"
WP8O_AUTHORITY_SEAL = "d7a8e91ec84af273d43ba03f5af86372a62b476a2a0dda2bfd4d988cf68cb263"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")

METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-paired-threshold-authority", WP8O_AUTHORITY_SEAL),
    ("protocol-status", "register-residency-claim-protocol-structurally-admitted"),
    ("admission-status", "blocked"),
    ("default-mode", "static-no-host-no-network-no-clock-no-execution"),
    ("claim-status", "not-admitted"),
    ("claim-class", "exact-four-kernel-register-residency-threshold-observation"),
    ("claim-scope", "exact-host-commit-bundle-candidate-and-four-kernels-only"),
    ("target", "x86_64-unknown-linux-gnu"),
)
CLASSES = (
    (
        "01",
        "exact-four-kernel-register-residency-threshold-observation",
        "permitted-only-after-all-gates",
    ),
    ("02", "language-wide-naux-speedup", "forbidden"),
    ("03", "c-cpp-or-compiler-leadership", "forbidden"),
    ("04", "unmeasured-workload-or-platform-extrapolation", "forbidden"),
)
GATES = (
    ("01", "public-protocol", "required", "exact-tracked-wp8b-through-wp8p-commit-and-green-ci"),
    ("02", "eligible-bundle", "required", "exact-public-wp8m-root-and-inventory"),
    ("03", "paired-evidence", "required", "exact-wp8n-read-only-replay"),
    ("04", "paired-threshold", "required", "exact-wp8o-all-four-kernel-pass"),
    ("05", "claim-text", "required", "host-commit-bundle-threshold-and-four-kernel-qualified"),
    ("06", "public-artifacts", "required", "bundle-candidate-and-reproduction-receipt-addressable"),
    ("07", "release-approval", "required", "distinct-explicit-owner-approval"),
    ("08", "non-self-admission", "required", "checker-cannot-grant-claim-authority"),
)
BLOCKERS = (
    ("01", "tracked-public-protocol-acceptance-unavailable"),
    ("02", "eligible-public-paired-bundle-unavailable"),
    ("03", "exact-public-claim-request-unavailable"),
    ("04", "distinct-release-approval-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8P"),
    ("authority-id", "s4-register-residency-claim-admission-v1"),
    ("protocol-status", "register-residency-claim-protocol-structurally-admitted"),
    ("admission-status", "blocked"),
    ("claim-status", "not-admitted"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-claim-admission.yml",
    "distribution/s4-performance/WP8P-CLAIM.tsv",
    "distribution/s4-performance/WP8P-NONCLAIMS.md",
    "distribution/s4-performance/WP8P-README.md",
    "scripts/s4_register_residency_claim_admission.py",
    "scripts/tests/test_s4_register_residency_claim_admission_refusal.py",
    "scripts/tests/test_s4_register_residency_claim_admission_static.py",
)


class ClaimAdmissionError(RuntimeError):
    """A fail-closed S4-WP8P protocol error."""


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
    threshold: wp8o.Admission
    report: bytes
    report_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    try:
        raw = wp8o.wp8n._read_regular(path, path.name)
        lines = wp8o.wp8n._canonical(raw, path.name)
    except wp8o.wp8n.PairedEvidenceError as error:
        raise ClaimAdmissionError(f"cannot read sealed file: {path.name}") from error
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise ClaimAdmissionError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if (
        len(fields) != 2
        or not HASH_RE.fullmatch(fields[1])
        or _sha256(domain + body) != fields[1]
    ):
        raise ClaimAdmissionError(f"{path.name} seal drifted")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL:
        raise ClaimAdmissionError("WP8P contract identity drifted")
    expected = [f"meta\t{key}\t{value}" for key, value in METADATA]
    expected.extend(
        f"class\t{ordinal}\t{name}\t{status}" for ordinal, name, status in CLASSES
    )
    expected.extend(
        f"gate\t{ordinal}\t{name}\t{status}\t{detail}"
        for ordinal, name, status, detail in GATES
    )
    expected.extend(f"blocker\t{ordinal}\t{name}" for ordinal, name in BLOCKERS)
    if rows != expected:
        raise ClaimAdmissionError("WP8P contract rows drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    prefix = [f"meta\t{key}\t{value}" for key, value in AUTHORITY_METADATA]
    prefix.extend(
        (
            "component\tclaim-contract\t"
            f"distribution/s4-performance/WP8P-CLAIM.tsv\t{contract_seal}",
            "parent\tpaired-threshold-authority\t"
            f"distribution/s4-performance/WP8O-AUTHORITY.tsv\t{WP8O_AUTHORITY_SEAL}",
        )
    )
    if rows[: len(prefix)] != prefix:
        raise ClaimAdmissionError("WP8P authority metadata or parent binding drifted")
    records = []
    for row in rows[len(prefix) :]:
        fields = row.split("\t")
        if (
            len(fields) != 6
            or fields[0] != "file"
            or not MODE_RE.fullmatch(fields[1])
            or not UINT_RE.fullmatch(fields[2])
            or not HASH_RE.fullmatch(fields[3])
            or fields[4] not in EXPECTED_FILES
            or fields[5] != "claim-admission"
        ):
            raise ClaimAdmissionError("WP8P authority file row is malformed")
        records.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise ClaimAdmissionError("WP8P authority inventory drifted")
    return Authority(tuple(records), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        try:
            raw = wp8o.wp8n._read_regular(path, record.path)
        except wp8o.wp8n.PairedEvidenceError as error:
            raise ClaimAdmissionError(
                f"bound WP8P file is not regular: {record.path}"
            ) from error
        mode = stat.S_IFREG | stat.S_IMODE(path.lstat().st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise ClaimAdmissionError(f"bound WP8P file drifted: {record.path}")


def _verify_static_boundary(root: Path) -> None:
    workflow = (
        root / ".github/workflows/s4-register-residency-claim-admission.yml"
    ).read_text()
    for token in (
        "scripts/s4_register_residency_claim_admission.py",
        "test_s4_register_residency_claim_admission_static",
        "test_s4_register_residency_claim_admission_refusal",
    ):
        if token not in workflow:
            raise ClaimAdmissionError("WP8P workflow omits a static gate")
    source = "\n".join((root / relative).read_text() for relative in EXPECTED_FILES)
    forbidden = (
        "--" + "bundle",
        "--" + "candidate",
        "--" + "request",
        "--" + "approve",
        "--" + "admit",
        "import " + "time",
        "import " + "subprocess",
        "import " + "socket",
        "import " + "urllib",
        "os." + "fork(",
        "os." + "execve(",
    )
    if any(token in source for token in forbidden):
        raise ClaimAdmissionError("WP8P exposes acquisition or admission capability")
    expected = {
        "WP8P-AUTHORITY.tsv",
        "WP8P-CLAIM.tsv",
        "WP8P-NONCLAIMS.md",
        "WP8P-README.md",
    }
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP8P-*")
        if path.is_file()
    }
    if actual != expected:
        raise ClaimAdmissionError("unexpected WP8P distribution artifact")


def _static_report(contract: Contract, authority: Authority) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"parent-paired-threshold-authority\t{WP8O_AUTHORITY_SEAL}",
        "protocol-status\tregister-residency-claim-protocol-structurally-admitted",
        "admission-status\tblocked",
        "mode\tstatic-no-host-no-network-no-clock-no-execution",
        "claim-status\tnot-admitted",
        f"blockers\t{len(BLOCKERS)}",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    threshold = wp8o.validate(root)
    if threshold.authority.seal != WP8O_AUTHORITY_SEAL:
        raise ClaimAdmissionError("WP8O parent authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP8P-CLAIM.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP8P-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_static_boundary(root)
    report, report_root = _static_report(contract, authority)
    return Admission(contract, authority, threshold, report, report_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args(argv)
    try:
        sys.stdout.buffer.write(validate(arguments.root).report)
        return 0
    except (
        ClaimAdmissionError,
        wp8o.PairedThresholdError,
        wp8o.wp8n.PairedEvidenceError,
        wp8o.wp8n.wp8m.PairedRunnerError,
        OSError,
        ValueError,
    ) as error:
        print(f"S4-WP8P validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
