#!/usr/bin/env python3
"""Validate the offline S4-WP8Q reviewed public-protocol receipt."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_claim_admission as wp8p


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PUBLIC-PROTOCOL-ACCEPTANCE-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PUBLIC-PROTOCOL-ACCEPTANCE-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PUBLIC-PROTOCOL-ACCEPTANCE-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-public-protocol:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-public-protocol:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-public-protocol:report:v1\0"
CONTRACT_SEAL = "a9be967cd9939eb355d0e8b01e55febd7f6b6886a664dc65da9b51ba4ac3257c"
WP8P_AUTHORITY_SEAL = "c2b582433f9c28c7b74b624f310754319446e7555d1aeb956b8d1d5b16c55c27"
TRACKED_COMMIT = "56b6447a13ac648c8e35e64daa34ddabb7e0b51c"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")

METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-claim-admission-authority", WP8P_AUTHORITY_SEAL),
    ("tracked-commit", TRACKED_COMMIT),
    ("repository", "x2t8/Naux"),
    ("branch", "main"),
    ("status", "public-protocol-acceptance-recorded"),
    ("observation-mode", "reviewed-static-public-record-no-network"),
    ("claim-status", "not-admitted"),
    ("target", "x86_64-unknown-linux-gnu"),
)
RUNS = (
    ("01", "ci", "33785721821", TRACKED_COMMIT, "success"),
    ("02", "formal-model", "33785721725", TRACKED_COMMIT, "success"),
    ("03", "formal-residency-bridge", "33785721753", TRACKED_COMMIT, "success"),
)
CLOSURES = (
    (
        "01",
        "tracked-public-protocol-acceptance-unavailable",
        "closed",
        "exact-tracked-commit-three-green-public-runs",
    ),
)
BLOCKERS = (
    ("01", "eligible-public-paired-bundle-unavailable"),
    ("02", "exact-public-claim-request-unavailable"),
    ("03", "distinct-release-approval-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8Q"),
    ("authority-id", "s4-register-residency-public-protocol-v1"),
    ("status", "public-protocol-acceptance-recorded"),
    ("admission-status", "blocked"),
    ("claim-status", "not-admitted"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-public-protocol.yml",
    "distribution/s4-performance/WP8Q-NONCLAIMS.md",
    "distribution/s4-performance/WP8Q-PUBLIC-PROTOCOL.tsv",
    "distribution/s4-performance/WP8Q-README.md",
    "scripts/s4_register_residency_public_protocol.py",
    "scripts/tests/test_s4_register_residency_public_protocol_refusal.py",
    "scripts/tests/test_s4_register_residency_public_protocol_static.py",
)


class PublicProtocolError(RuntimeError):
    """A fail-closed S4-WP8Q public-protocol receipt error."""


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
    parent: wp8p.Admission
    report: bytes
    report_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    try:
        raw = wp8p.wp8o.wp8n._read_regular(path, path.name)
        lines = wp8p.wp8o.wp8n._canonical(raw, path.name)
    except wp8p.wp8o.wp8n.PairedEvidenceError as error:
        raise PublicProtocolError(f"cannot read sealed file: {path.name}") from error
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise PublicProtocolError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if (
        len(fields) != 2
        or not HASH_RE.fullmatch(fields[1])
        or _sha256(domain + body) != fields[1]
    ):
        raise PublicProtocolError(f"{path.name} seal drifted")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL:
        raise PublicProtocolError("WP8Q contract identity drifted")
    expected = [f"meta\t{key}\t{value}" for key, value in METADATA]
    expected.extend(
        f"run\t{ordinal}\t{name}\t{run_id}\t{commit}\t{status}"
        for ordinal, name, run_id, commit, status in RUNS
    )
    expected.extend(
        f"closure\t{ordinal}\t{name}\t{status}\t{detail}"
        for ordinal, name, status, detail in CLOSURES
    )
    expected.extend(f"blocker\t{ordinal}\t{name}" for ordinal, name in BLOCKERS)
    if rows != expected:
        raise PublicProtocolError("WP8Q contract rows drifted")
    if not COMMIT_RE.fullmatch(TRACKED_COMMIT):
        raise PublicProtocolError("WP8Q tracked commit is malformed")
    if any(not UINT_RE.fullmatch(run_id) or int(run_id) == 0 for _, _, run_id, _, _ in RUNS):
        raise PublicProtocolError("WP8Q public run identity is malformed")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    prefix = [f"meta\t{key}\t{value}" for key, value in AUTHORITY_METADATA]
    prefix.extend(
        (
            "component\tpublic-protocol-contract\t"
            f"distribution/s4-performance/WP8Q-PUBLIC-PROTOCOL.tsv\t{contract_seal}",
            "parent\tclaim-admission-authority\t"
            f"distribution/s4-performance/WP8P-AUTHORITY.tsv\t{WP8P_AUTHORITY_SEAL}",
        )
    )
    if rows[: len(prefix)] != prefix:
        raise PublicProtocolError("WP8Q authority metadata or parent binding drifted")
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
            or fields[5] != "public-protocol"
        ):
            raise PublicProtocolError("WP8Q authority file row is malformed")
        records.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise PublicProtocolError("WP8Q authority inventory drifted")
    return Authority(tuple(records), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        try:
            raw = wp8p.wp8o.wp8n._read_regular(path, record.path)
        except wp8p.wp8o.wp8n.PairedEvidenceError as error:
            raise PublicProtocolError(
                f"bound WP8Q file is not regular: {record.path}"
            ) from error
        mode = stat.S_IFREG | stat.S_IMODE(path.lstat().st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise PublicProtocolError(f"bound WP8Q file drifted: {record.path}")


def _verify_static_boundary(root: Path) -> None:
    workflow = (
        root / ".github/workflows/s4-register-residency-public-protocol.yml"
    ).read_text()
    for token in (
        "scripts/s4_register_residency_public_protocol.py",
        "test_s4_register_residency_public_protocol_static",
        "test_s4_register_residency_public_protocol_refusal",
    ):
        if token not in workflow:
            raise PublicProtocolError("WP8Q workflow omits a static gate")
    source = "\n".join((root / relative).read_text() for relative in EXPECTED_FILES)
    forbidden = (
        "import " + "subprocess",
        "import " + "socket",
        "import " + "urllib",
        "import " + "requests",
        "import " + "time",
        "curl " + "http",
        "gh " + "run",
        "os." + "system(",
        "os." + "execve(",
    )
    if any(token in source for token in forbidden):
        raise PublicProtocolError("WP8Q exposes network, process, or acquisition capability")
    expected = {
        "WP8Q-AUTHORITY.tsv",
        "WP8Q-NONCLAIMS.md",
        "WP8Q-PUBLIC-PROTOCOL.tsv",
        "WP8Q-README.md",
    }
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP8Q-*")
        if path.is_file()
    }
    if actual != expected:
        raise PublicProtocolError("unexpected WP8Q distribution artifact")


def _static_report(contract: Contract, authority: Authority) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"parent-claim-admission-authority\t{WP8P_AUTHORITY_SEAL}",
        f"tracked-commit\t{TRACKED_COMMIT}",
        f"ci-run\t{RUNS[0][2]}",
        f"formal-model-run\t{RUNS[1][2]}",
        f"formal-residency-bridge-run\t{RUNS[2][2]}",
        "public-protocol-gate\tclosed",
        "observation-mode\treviewed-static-public-record-no-network",
        "admission-status\tblocked",
        "claim-status\tnot-admitted",
        f"blockers\t{len(BLOCKERS)}",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    parent = wp8p.validate(root)
    if parent.authority.seal != WP8P_AUTHORITY_SEAL:
        raise PublicProtocolError("WP8P parent authority drifted")
    contract = parse_contract(
        root / "distribution/s4-performance/WP8Q-PUBLIC-PROTOCOL.tsv"
    )
    authority = parse_authority(
        root / "distribution/s4-performance/WP8Q-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_static_boundary(root)
    report, report_root = _static_report(contract, authority)
    return Admission(contract, authority, parent, report, report_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args(argv)
    try:
        sys.stdout.buffer.write(validate(arguments.root).report)
        return 0
    except (
        PublicProtocolError,
        wp8p.ClaimAdmissionError,
        wp8p.wp8o.PairedThresholdError,
        wp8p.wp8o.wp8n.PairedEvidenceError,
        wp8p.wp8o.wp8n.wp8m.PairedRunnerError,
        OSError,
        ValueError,
    ) as error:
        print(f"S4-WP8Q validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
