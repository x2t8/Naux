#!/usr/bin/env python3
"""Validate the WP8S approval or admit its one exact replayed observation."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_claim_admission as wp8p
import s4_register_residency_paired_threshold as wp8o
import s4_register_residency_public_bundle as wp8r


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-EXACT-CLAIM-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-EXACT-CLAIM-AUTHORITY\t1"
STATIC_REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-EXACT-CLAIM-STATIC\t1"
ADMISSION_REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-EXACT-CLAIM-ADMISSION\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-exact-claim:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-exact-claim:authority:v1\0"
STATIC_REPORT_DOMAIN = b"NAUX:s4-register-residency-exact-claim:static:v1\0"
ADMISSION_REPORT_DOMAIN = b"NAUX:s4-register-residency-exact-claim:admission:v1\0"
CONTRACT_SEAL = "07d2fa5bc99ecf7eba10d78494f6f04e984c0c8a73605af12627151b1dc93000"
WP8P_AUTHORITY_SEAL = "c2b582433f9c28c7b74b624f310754319446e7555d1aeb956b8d1d5b16c55c27"
WP8R_AUTHORITY_SEAL = "2d58aa292d83e89cf8d2e691b46968f2c31f8acad45d4f89a6063e92f0b30957"
WP8O_AUTHORITY_SEAL = "582e3b7036a1909ed0234c1c421226891a52184c819a1b3f0d8d96b8b4c3209c"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")


@dataclass(frozen=True)
class Identity:
    repository: str = "x2t8/Naux"
    release_tag: str = "s4-wp8m-56b6447"
    release_id: str = "382979878"
    release_url: str = "https://github.com/x2t8/Naux/releases/tag/s4-wp8m-56b6447"
    release_author: str = "x2t8"
    release_updated_at: str = "2026-09-05T06:31:18Z"
    release_body_bytes: int = 1256
    release_body_sha256: str = "d4127d9b3870765e04dc8ea22ea66d6344d4c24b05e26162db30e68430cf59f6"
    archive_id: str = "544820377"
    archive_name: str = "naux-s4-register-residency-paired-56b6447a13ac648c8e35e64daa34ddabb7e0b51c.tar.gz"
    archive_bytes: int = 11699
    archive_sha256: str = "c94dd7bb8743f2a740227e57b75a51e56b0ff309492f2277628a297de0cfee69"
    receipt_id: str = "544820376"
    receipt_name: str = "naux-s4-register-residency-paired-56b6447a13ac648c8e35e64daa34ddabb7e0b51c.tar.gz.receipt.tsv"
    receipt_bytes: int = 956
    receipt_sha256: str = "6441d7effac7f21a692ff28ee0504473c90f7cd77a2d8d599888e69c33d45d81"
    source_commit: str = "56b6447a13ac648c8e35e64daa34ddabb7e0b51c"
    host_attestation: str = "85eae3c1b490e94f8c5ca06f224965e79bd66a54ab3828343499a282eb8ead9c"
    bundle_root: str = "81fbe0034fb2561d8b86f31552d170ccb4f7273545fcc1596e46ccb7f1c02bb9"
    session_root: str = "77c5447ef1db3bf95a517926383f3ff17eebd53dfa832cef98348a9d337ecc04"
    evidence_root: str = "16f5c8eec57f4a1c36a2f1a02d04f81684bfd9f1b859d836995525323f0e12c5"
    public_intake_root: str = "a77a45ddf18b4611a569acb65bb1347370ef021f354b46ff0bfbed671b67d2fc"
    threshold_root: str = "9bb2df954d9e8f03bc5119906fcdc3e7a5ccc6aaa0601809ff762489f102d79f"
    claim_bytes: int = 703
    claim_sha256: str = "4c2067dc2734669e4ac9f98d453c5c54180d3cfb59760cffd38236ac1bf19505"


EXPECTED = Identity()
METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-claim-protocol-authority", WP8P_AUTHORITY_SEAL),
    ("parent-public-bundle-authority", WP8R_AUTHORITY_SEAL),
    ("parent-paired-threshold-authority", WP8O_AUTHORITY_SEAL),
    ("claim-class", "exact-four-kernel-register-residency-threshold-observation"),
    ("claim-scope", "exact-host-commit-bundle-threshold-and-four-kernels-only"),
    ("static-status", "approval-recorded-evidence-required"),
    ("dynamic-status", "admitted-only-after-exact-read-only-replay"),
    ("target", "x86_64-unknown-linux-gnu"),
)
GATES = (
    ("01", "parent-protocol", "required", "exact-wp8p-authority"),
    ("02", "public-bundle", "required", "exact-wp8r-read-only-intake"),
    ("03", "paired-evidence", "required", "exact-wp8n-evidence-root"),
    ("04", "paired-threshold", "required", "exact-wp8o-four-of-four-pass"),
    ("05", "claim-text", "required", "exact-bytes-and-sha256"),
    ("06", "public-assets", "required", "exact-release-locators-sizes-and-sha256"),
    ("07", "owner-approval", "required", "exact-public-release-body-snapshot"),
    ("08", "non-self-admission", "required", "checker-cannot-create-or-edit-approval"),
    ("09", "non-extrapolation", "required", "exact-scope-only"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-exact-claim.yml",
    "distribution/s4-performance/WP8S-APPROVED-CLAIM.txt",
    "distribution/s4-performance/WP8S-CLAIM-ADMISSION.tsv",
    "distribution/s4-performance/WP8S-NONCLAIMS.md",
    "distribution/s4-performance/WP8S-README.md",
    "distribution/s4-performance/WP8S-RELEASE-APPROVAL.md",
    "scripts/s4_register_residency_exact_claim.py",
    "scripts/tests/test_s4_register_residency_exact_claim_replay.py",
    "scripts/tests/test_s4_register_residency_exact_claim_static.py",
)


class ExactClaimError(RuntimeError):
    """A fail-closed WP8S validation error."""


@dataclass(frozen=True)
class FileRecord:
    mode: int
    size: int
    sha256: str
    path: str


@dataclass(frozen=True)
class StaticAdmission:
    contract_seal: str
    authority_seal: str
    files: tuple[FileRecord, ...]
    protocol: wp8p.Admission
    public: wp8r.Admission
    threshold: wp8o.Admission
    claim: bytes
    static_report: bytes
    static_root: str


@dataclass(frozen=True)
class ExactAdmission:
    intake: wp8r.Intake
    decisions: tuple[wp8o.KernelDecision, ...]
    threshold_report: bytes
    report: bytes
    report_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _regular(path: Path, label: str, maximum: int = 128 * 1024) -> bytes:
    try:
        raw = wp8r.wp8n._read_regular(path, label, maximum)
    except wp8r.wp8n.PairedEvidenceError as error:
        raise ExactClaimError(f"cannot read {label}") from error
    return raw


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    raw = _regular(path, path.name)
    try:
        lines = wp8r.wp8n._canonical(raw, path.name)
    except wp8r.wp8n.PairedEvidenceError as error:
        raise ExactClaimError(f"{path.name} is not canonical") from error
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise ExactClaimError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if (
        len(fields) != 2
        or not HASH_RE.fullmatch(fields[1])
        or _sha256(domain + body) != fields[1]
    ):
        raise ExactClaimError(f"{path.name} seal drifted")
    return lines[1:-1], fields[1]


def _expected_contract_rows() -> list[str]:
    rows = [f"meta\t{key}\t{value}" for key, value in METADATA]
    rows.extend((
        f"release\trepository\t{EXPECTED.repository}",
        f"release\ttag\t{EXPECTED.release_tag}",
        f"release\tid\t{EXPECTED.release_id}",
        f"release\turl\t{EXPECTED.release_url}",
        f"release\tauthor\t{EXPECTED.release_author}",
        f"release\tupdated-at\t{EXPECTED.release_updated_at}",
        f"release\tbody-bytes\t{EXPECTED.release_body_bytes}",
        f"release\tbody-sha256\t{EXPECTED.release_body_sha256}",
        f"asset\tarchive-id\t{EXPECTED.archive_id}",
        f"asset\tarchive-name\t{EXPECTED.archive_name}",
        f"asset\tarchive-bytes\t{EXPECTED.archive_bytes}",
        f"asset\tarchive-sha256\t{EXPECTED.archive_sha256}",
        f"asset\treceipt-id\t{EXPECTED.receipt_id}",
        f"asset\treceipt-name\t{EXPECTED.receipt_name}",
        f"asset\treceipt-bytes\t{EXPECTED.receipt_bytes}",
        f"asset\treceipt-sha256\t{EXPECTED.receipt_sha256}",
        f"evidence\tsource-commit\t{EXPECTED.source_commit}",
        f"evidence\thost-attestation\t{EXPECTED.host_attestation}",
        f"evidence\tbundle-root\t{EXPECTED.bundle_root}",
        f"evidence\tsession-root\t{EXPECTED.session_root}",
        f"evidence\tevidence-root\t{EXPECTED.evidence_root}",
        f"evidence\tpublic-intake-root\t{EXPECTED.public_intake_root}",
        f"evidence\tthreshold-root\t{EXPECTED.threshold_root}",
        "evidence\tkernel-count\t4",
        "evidence\tpairs-per-kernel\t30",
        "claim\tpath\tdistribution/s4-performance/WP8S-APPROVED-CLAIM.txt",
        f"claim\tbytes\t{EXPECTED.claim_bytes}",
        f"claim\tsha256\t{EXPECTED.claim_sha256}",
        "approval\tpath\tdistribution/s4-performance/WP8S-RELEASE-APPROVAL.md",
        "approval\tstatus\texplicit-owner-approved",
        "approval\tauthority\tgithub-release-author-x2t8",
        "approval\tdurability\tpublic-release-plus-tracked-snapshot",
        "approval\tsignature-status\tnot-a-cryptographic-signature",
    ))
    rows.extend(
        f"gate\t{ordinal}\t{name}\t{status}\t{detail}"
        for ordinal, name, status, detail in GATES
    )
    return rows


def _parse_contract(path: Path) -> str:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL or rows != _expected_contract_rows():
        raise ExactClaimError("WP8S contract identity drifted")
    return seal


def _parse_authority(path: Path, contract_seal: str) -> tuple[tuple[FileRecord, ...], str]:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    prefix = [
        "meta\tscope\tS4",
        "meta\twork-package\tS4-WP8S",
        "meta\tauthority-id\ts4-register-residency-exact-claim-v1",
        "meta\tstatic-status\tapproval-recorded-evidence-required",
        "meta\tdynamic-status\texact-replay-admission-enabled",
        f"meta\tfile-count\t{len(EXPECTED_FILES)}",
        "component\tclaim-contract\tdistribution/s4-performance/WP8S-CLAIM-ADMISSION.tsv\t" + contract_seal,
        "parent\tclaim-protocol-authority\tdistribution/s4-performance/WP8P-AUTHORITY.tsv\t" + WP8P_AUTHORITY_SEAL,
        "parent\tpublic-bundle-authority\tdistribution/s4-performance/WP8R-AUTHORITY.tsv\t" + WP8R_AUTHORITY_SEAL,
        "parent\tpaired-threshold-authority\tdistribution/s4-performance/WP8O-AUTHORITY.tsv\t" + WP8O_AUTHORITY_SEAL,
    ]
    if rows[: len(prefix)] != prefix:
        raise ExactClaimError("WP8S authority metadata drifted")
    records = []
    for row in rows[len(prefix):]:
        fields = row.split("\t")
        if (
            len(fields) != 6
            or fields[0] != "file"
            or not MODE_RE.fullmatch(fields[1])
            or not UINT_RE.fullmatch(fields[2])
            or not HASH_RE.fullmatch(fields[3])
            or fields[4] not in EXPECTED_FILES
            or fields[5] != "exact-claim"
        ):
            raise ExactClaimError("WP8S authority file row is malformed")
        records.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise ExactClaimError("WP8S authority inventory drifted")
    return tuple(records), seal


def _verify_files(root: Path, records: tuple[FileRecord, ...]) -> None:
    for record in records:
        path = root / record.path
        raw = _regular(path, record.path)
        mode = stat.S_IFREG | stat.S_IMODE(path.lstat().st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise ExactClaimError(f"bound WP8S file drifted: {record.path}")
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP8S-*")
        if path.is_file()
    }
    expected = {
        "WP8S-APPROVED-CLAIM.txt",
        "WP8S-AUTHORITY.tsv",
        "WP8S-CLAIM-ADMISSION.tsv",
        "WP8S-NONCLAIMS.md",
        "WP8S-README.md",
        "WP8S-RELEASE-APPROVAL.md",
    }
    if actual != expected:
        raise ExactClaimError("unexpected WP8S distribution artifact")


def _verify_claim_and_approval(root: Path) -> bytes:
    claim = _regular(root / "distribution/s4-performance/WP8S-APPROVED-CLAIM.txt", "approved claim")
    approval = _regular(root / "distribution/s4-performance/WP8S-RELEASE-APPROVAL.md", "release approval")
    if len(claim) != EXPECTED.claim_bytes or _sha256(claim) != EXPECTED.claim_sha256:
        raise ExactClaimError("approved claim bytes drifted")
    if len(approval) != EXPECTED.release_body_bytes or _sha256(approval) != EXPECTED.release_body_sha256:
        raise ExactClaimError("release approval snapshot drifted")
    if claim.rstrip(b"\n") not in approval.replace(b"`", b""):
        raise ExactClaimError("release approval does not contain the exact claim")
    return claim


def _report(magic: str, domain: bytes, rows: tuple[str, ...]) -> tuple[bytes, str]:
    body = b"".join(f"{row}\n".encode() for row in (magic, *rows))
    root = _sha256(domain + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> StaticAdmission:
    root = root.resolve(strict=True)
    protocol = wp8p.validate(root)
    public = wp8r.validate(root)
    threshold = wp8o.validate(root)
    if protocol.authority.seal != WP8P_AUTHORITY_SEAL:
        raise ExactClaimError("WP8P parent authority drifted")
    if public.authority.seal != WP8R_AUTHORITY_SEAL:
        raise ExactClaimError("WP8R parent authority drifted")
    if threshold.authority.seal != WP8O_AUTHORITY_SEAL:
        raise ExactClaimError("WP8O parent authority drifted")
    contract = _parse_contract(root / "distribution/s4-performance/WP8S-CLAIM-ADMISSION.tsv")
    files, authority = _parse_authority(root / "distribution/s4-performance/WP8S-AUTHORITY.tsv", contract)
    _verify_files(root, files)
    claim = _verify_claim_and_approval(root)
    report, report_root = _report(STATIC_REPORT_MAGIC, STATIC_REPORT_DOMAIN, (
        f"contract\t{contract}",
        f"authority\t{authority}",
        f"claim-sha256\t{EXPECTED.claim_sha256}",
        f"release-body-sha256\t{EXPECTED.release_body_sha256}",
        "approval-status\texplicit-owner-approved",
        "evidence-status\texact-public-archive-required",
        "admission-status\tblocked-without-replay",
        "claim-status\tnot-admitted",
    ))
    return StaticAdmission(contract, authority, files, protocol, public, threshold, claim, report, report_root)


def _verify_input(path: Path, name: str, size: int, digest: str, label: str) -> None:
    if path.name != name:
        raise ExactClaimError(f"{label} filename drifted")
    raw = _regular(path, label, max(size + 1, 128 * 1024))
    if len(raw) != size or _sha256(raw) != digest:
        raise ExactClaimError(f"{label} size or SHA-256 drifted")


def admit(archive: Path, receipt: Path, static: StaticAdmission) -> ExactAdmission:
    _verify_input(archive, EXPECTED.archive_name, EXPECTED.archive_bytes, EXPECTED.archive_sha256, "archive")
    _verify_input(receipt, EXPECTED.receipt_name, EXPECTED.receipt_bytes, EXPECTED.receipt_sha256, "receipt")
    intake = wp8r.intake_archive(archive, receipt, static.public)
    decisions, threshold_report, threshold_root, passed = wp8o._candidate_report(
        static.threshold, intake.replay
    )
    observed = (
        intake.receipt.repository,
        intake.receipt.release_tag,
        intake.receipt.archive_sha256,
        intake.replay.manifest.source_commit,
        intake.replay.manifest.host_attestation,
        intake.replay.manifest.root,
        intake.replay.manifest.session_root,
        intake.replay.evidence_root,
        intake.report_root,
        threshold_root,
    )
    expected = (
        EXPECTED.repository,
        EXPECTED.release_tag,
        EXPECTED.archive_sha256,
        EXPECTED.source_commit,
        EXPECTED.host_attestation,
        EXPECTED.bundle_root,
        EXPECTED.session_root,
        EXPECTED.evidence_root,
        EXPECTED.public_intake_root,
        EXPECTED.threshold_root,
    )
    if observed != expected:
        raise ExactClaimError("replayed public evidence identity drifted")
    if not passed or len(decisions) != 4 or any(
        item.sample_pairs != 30 or not item.kernel_pass for item in decisions
    ):
        raise ExactClaimError("WP8O did not pass all four exact kernel gates")
    report, report_root = _report(ADMISSION_REPORT_MAGIC, ADMISSION_REPORT_DOMAIN, (
        f"contract\t{static.contract_seal}",
        f"authority\t{static.authority_seal}",
        f"release\t{EXPECTED.release_url}",
        f"release-author\t{EXPECTED.release_author}",
        f"release-body-sha256\t{EXPECTED.release_body_sha256}",
        f"archive-sha256\t{EXPECTED.archive_sha256}",
        f"receipt-sha256\t{EXPECTED.receipt_sha256}",
        f"public-intake-root\t{intake.report_root}",
        f"bundle-root\t{intake.replay.manifest.root}",
        f"session-root\t{intake.replay.manifest.session_root}",
        f"host-attestation\t{intake.replay.manifest.host_attestation}",
        f"source-commit\t{intake.replay.manifest.source_commit}",
        f"evidence-root\t{intake.replay.evidence_root}",
        f"threshold-root\t{threshold_root}",
        f"claim-sha256\t{EXPECTED.claim_sha256}",
        "passing-kernels\t4",
        "pairs-per-kernel\t30",
        "approval-status\texplicit-owner-approved",
        "approval-signature-status\tnot-a-cryptographic-signature",
        "admission-scope\texact-host-commit-artifacts-protocol-and-four-kernels-only",
        "claim-status\tadmitted-exact-observation",
    ))
    return ExactAdmission(intake, decisions, threshold_report, report, report_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--receipt", type=Path)
    arguments = parser.parse_args(argv)
    if (arguments.archive is None) != (arguments.receipt is None):
        parser.error("--archive and --receipt must be supplied together")
    try:
        static = validate(arguments.root)
        report = static.static_report if arguments.archive is None else admit(
            arguments.archive, arguments.receipt, static
        ).report
        sys.stdout.buffer.write(report)
        return 0
    except (
        ExactClaimError,
        wp8p.ClaimAdmissionError,
        wp8r.wp8q.PublicProtocolError,
        wp8r.PublicBundleError,
        wp8o.PairedThresholdError,
        wp8r.wp8n.PairedEvidenceError,
        wp8r.wp8n.wp8m.PairedRunnerError,
        wp8r.wp8n.wp8m.wp8k.CandidateRunnerError,
        wp8r.wp8n.wp8m.wp7c.RunnerError,
        OSError,
        ValueError,
    ) as error:
        print(f"S4-WP8S validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
