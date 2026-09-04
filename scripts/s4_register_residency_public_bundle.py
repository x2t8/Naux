#!/usr/bin/env python3
"""Package or verify an S4-WP8R public paired-bundle candidate."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_paired_evidence as wp8n
import s4_register_residency_public_protocol as wp8q


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PUBLIC-BUNDLE-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PUBLIC-BUNDLE-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PUBLIC-BUNDLE-REPORT\t1"
RECEIPT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PUBLIC-BUNDLE-RECEIPT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-public-bundle:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-public-bundle:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-public-bundle:report:v1\0"
RECEIPT_DOMAIN = b"NAUX:s4-register-residency-public-bundle:receipt:v1\0"
CONTRACT_SEAL = "f9a5c628fcfbfb201fe28108fa41246e5e225b24689caa9b2149578159b96781"
WP8Q_AUTHORITY_SEAL = "ba48acae4b11ee2ceba6873ff45b58998eac43eca76722ff466df4325dfcf952"
WP8N_AUTHORITY_SEAL = "c8891c211c5469f1c4e5009674a2b11c68c39839b04712f5e57ebf77165e678e"
REPOSITORY = "x2t8/Naux"
TARGET = "x86_64-unknown-linux-gnu"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 24 * 1024 * 1024
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
POSITIVE_RE = re.compile(r"[1-9][0-9]*\Z")
TAG_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126})\Z")

METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-public-protocol-authority", WP8Q_AUTHORITY_SEAL),
    ("parent-paired-evidence-authority", WP8N_AUTHORITY_SEAL),
    ("repository", REPOSITORY),
    ("tracked-commit", wp8q.TRACKED_COMMIT),
    ("status", "public-bundle-intake-structurally-admitted"),
    ("default-mode", "static-no-bundle-no-archive-no-network-no-execution"),
    ("package-mode", "explicit-local-deterministic-archive"),
    ("intake-mode", "explicit-read-only-archive-replay"),
    ("archive-policy", "exact-single-root-ustar-gzip-normalized-metadata"),
    ("locator-policy", "canonical-github-release-url-shape-no-reachability-claim"),
    ("claim-status", "not-admitted"),
    ("target", TARGET),
)
GATES = (
    ("01", "static-isolation", "required", "no-bundle-no-archive-no-network-no-execution"),
    ("02", "archive-envelope", "required", "bounded-gzip-ustar-normalized-no-links"),
    ("03", "archive-inventory", "required", "single-root-exact-wp8m-inventory"),
    ("04", "receipt-integrity", "required", "exact-size-sha256-and-domain-root"),
    ("05", "paired-replay", "required", "exact-wp8n-read-only-replay"),
    ("06", "identity-coherence", "required", "commit-bundle-session-host-and-evidence"),
    ("07", "locator-boundary", "required", "canonical-shape-without-network-observation"),
    ("08", "claim-boundary", "required", "package-and-intake-never-admit-claim"),
)
CLOSURES = (
    (
        "01",
        "public-paired-bundle-packaging-and-intake-unavailable",
        "closed",
        "wp8r-deterministic-package-and-read-only-replay",
    ),
)
BLOCKERS = (
    ("01", "eligible-public-paired-bundle-unavailable"),
    ("02", "exact-public-claim-request-unavailable"),
    ("03", "distinct-release-approval-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8R"),
    ("authority-id", "s4-register-residency-public-bundle-v1"),
    ("status", "public-bundle-intake-structurally-admitted"),
    ("admission-status", "blocked"),
    ("claim-status", "not-admitted"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-public-bundle.yml",
    "distribution/s4-performance/WP8R-PUBLIC-BUNDLE.tsv",
    "distribution/s4-performance/WP8R-NONCLAIMS.md",
    "distribution/s4-performance/WP8R-README.md",
    "scripts/s4_register_residency_public_bundle.py",
    "scripts/tests/test_s4_register_residency_public_bundle_intake.py",
    "scripts/tests/test_s4_register_residency_public_bundle_static.py",
)
ARCHIVE_DIRECTORIES = ("", "artifacts", "artifacts/baseline", "artifacts/candidate")
ARCHIVE_FILES = ("MANIFEST.tsv",) + wp8n.EXPECTED_BUNDLE_FILES


class PublicBundleError(RuntimeError):
    """A fail-closed S4-WP8R package or intake error."""


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
    protocol: wp8q.Admission
    evidence: wp8n.Admission
    report: bytes
    report_root: str


@dataclass(frozen=True)
class PublicationReceipt:
    repository: str
    release_tag: str
    asset_name: str
    asset_url: str
    archive_bytes: int
    archive_sha256: str
    bundle_root: str
    session_root: str
    host_attestation: str
    source_commit: str
    evidence_root: str
    root: str


@dataclass(frozen=True)
class Intake:
    receipt: PublicationReceipt
    replay: wp8n.Replay
    report: bytes
    report_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    try:
        raw = wp8n._read_regular(path, path.name)
        lines = wp8n._canonical(raw, path.name)
    except wp8n.PairedEvidenceError as error:
        raise PublicBundleError(f"cannot read sealed file: {path.name}") from error
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise PublicBundleError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if (
        len(fields) != 2
        or not HASH_RE.fullmatch(fields[1])
        or _sha256(domain + body) != fields[1]
    ):
        raise PublicBundleError(f"{path.name} seal drifted")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL:
        raise PublicBundleError("WP8R contract identity drifted")
    expected = [f"meta\t{key}\t{value}" for key, value in METADATA]
    expected.extend(
        f"gate\t{ordinal}\t{name}\t{status}\t{detail}"
        for ordinal, name, status, detail in GATES
    )
    expected.extend(
        f"closure\t{ordinal}\t{name}\t{status}\t{detail}"
        for ordinal, name, status, detail in CLOSURES
    )
    expected.extend(f"blocker\t{ordinal}\t{name}" for ordinal, name in BLOCKERS)
    if rows != expected:
        raise PublicBundleError("WP8R contract rows drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    prefix = [f"meta\t{key}\t{value}" for key, value in AUTHORITY_METADATA]
    prefix.extend(
        (
            "component\tpublic-bundle-contract\t"
            f"distribution/s4-performance/WP8R-PUBLIC-BUNDLE.tsv\t{contract_seal}",
            "parent\tpublic-protocol-authority\t"
            f"distribution/s4-performance/WP8Q-AUTHORITY.tsv\t{WP8Q_AUTHORITY_SEAL}",
            "parent\tpaired-evidence-authority\t"
            f"distribution/s4-performance/WP8N-AUTHORITY.tsv\t{WP8N_AUTHORITY_SEAL}",
        )
    )
    if rows[: len(prefix)] != prefix:
        raise PublicBundleError("WP8R authority metadata or parent binding drifted")
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
            or fields[5] != "public-bundle"
        ):
            raise PublicBundleError("WP8R authority file row is malformed")
        records.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise PublicBundleError("WP8R authority inventory drifted")
    return Authority(tuple(records), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        try:
            raw = wp8n._read_regular(path, record.path)
        except wp8n.PairedEvidenceError as error:
            raise PublicBundleError(
                f"bound WP8R file is not regular: {record.path}"
            ) from error
        mode = stat.S_IFREG | stat.S_IMODE(path.lstat().st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise PublicBundleError(f"bound WP8R file drifted: {record.path}")


def _verify_static_boundary(root: Path) -> None:
    workflow = (
        root / ".github/workflows/s4-register-residency-public-bundle.yml"
    ).read_text()
    for token in (
        "scripts/s4_register_residency_public_bundle.py",
        "test_s4_register_residency_public_bundle_static",
        "test_s4_register_residency_public_bundle_intake",
    ):
        if token not in workflow:
            raise PublicBundleError("WP8R workflow omits a static gate")
    if any(token in workflow for token in ("--archive", "--receipt", "--package-bundle")):
        raise PublicBundleError("WP8R hosted workflow attempts external intake or packaging")
    source = (root / "scripts/s4_register_residency_public_bundle.py").read_text()
    forbidden = (
        "import " + "subprocess",
        "import " + "socket",
        "import " + "urllib",
        "import " + "requests",
        "import " + "time",
        "os." + "system(",
        "os." + "execve(",
    )
    if any(token in source for token in forbidden):
        raise PublicBundleError("WP8R exposes network, process, clock, or execution capability")
    expected = {
        "WP8R-AUTHORITY.tsv",
        "WP8R-NONCLAIMS.md",
        "WP8R-PUBLIC-BUNDLE.tsv",
        "WP8R-README.md",
    }
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP8R-*")
        if path.is_file()
    }
    if actual != expected:
        raise PublicBundleError("unexpected WP8R distribution artifact")


def _static_report(contract: Contract, authority: Authority) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"parent-public-protocol-authority\t{WP8Q_AUTHORITY_SEAL}",
        f"parent-paired-evidence-authority\t{WP8N_AUTHORITY_SEAL}",
        f"tracked-commit\t{wp8q.TRACKED_COMMIT}",
        "status\tpublic-bundle-intake-structurally-admitted",
        "mode\tstatic-no-bundle-no-archive-no-network-no-execution",
        "archive-status\tabsent",
        "public-reachability\tnot-observed",
        "admission-status\tblocked",
        "claim-status\tnot-admitted",
        f"blockers\t{len(BLOCKERS)}",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    protocol = wp8q.validate(root)
    evidence = wp8n.validate(root)
    if protocol.authority.seal != WP8Q_AUTHORITY_SEAL:
        raise PublicBundleError("WP8Q parent authority drifted")
    if evidence.authority.seal != WP8N_AUTHORITY_SEAL:
        raise PublicBundleError("WP8N parent authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP8R-PUBLIC-BUNDLE.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP8R-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_static_boundary(root)
    report, report_root = _static_report(contract, authority)
    return Admission(contract, authority, protocol, evidence, report, report_root)


def _asset_name(commit: str) -> str:
    return f"naux-s4-register-residency-paired-{commit}.tar.gz"


def _asset_url(tag: str, asset_name: str) -> str:
    return f"https://github.com/{REPOSITORY}/releases/download/{tag}/{asset_name}"


def _receipt_bytes(
    release_tag: str,
    asset_name: str,
    archive: bytes,
    replay: wp8n.Replay,
) -> bytes:
    if not TAG_RE.fullmatch(release_tag):
        raise PublicBundleError("release tag is malformed")
    rows = (
        RECEIPT_MAGIC,
        f"repository\t{REPOSITORY}",
        f"release-tag\t{release_tag}",
        f"asset-name\t{asset_name}",
        f"asset-url\t{_asset_url(release_tag, asset_name)}",
        f"archive-bytes\t{len(archive)}",
        f"archive-sha256\t{_sha256(archive)}",
        f"bundle-root\t{replay.manifest.root}",
        f"session-root\t{replay.manifest.session_root}",
        f"host-attestation\t{replay.manifest.host_attestation}",
        f"source-commit\t{replay.manifest.source_commit}",
        f"evidence-root\t{replay.evidence_root}",
        "public-reachability\tnot-observed",
        "claim-status\tnot-admitted",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    return body + f"receipt-root\t{_sha256(RECEIPT_DOMAIN + body)}\n".encode()


def parse_receipt(path: Path) -> PublicationReceipt:
    try:
        raw = wp8n._read_regular(path, "public bundle receipt", 64 * 1024)
        lines = wp8n._canonical(raw, "public bundle receipt")
    except wp8n.PairedEvidenceError as error:
        raise PublicBundleError("cannot read public bundle receipt") from error
    keys = (
        "repository",
        "release-tag",
        "asset-name",
        "asset-url",
        "archive-bytes",
        "archive-sha256",
        "bundle-root",
        "session-root",
        "host-attestation",
        "source-commit",
        "evidence-root",
        "public-reachability",
        "claim-status",
    )
    if len(lines) != len(keys) + 2 or lines[0] != RECEIPT_MAGIC:
        raise PublicBundleError("public bundle receipt shape drifted")
    values: dict[str, str] = {}
    for expected_key, line in zip(keys, lines[1:-1], strict=True):
        fields = line.split("\t")
        if len(fields) != 2 or fields[0] != expected_key:
            raise PublicBundleError("public bundle receipt field order drifted")
        values[fields[0]] = fields[1]
    root_fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if (
        len(root_fields) != 2
        or root_fields[0] != "receipt-root"
        or not HASH_RE.fullmatch(root_fields[1])
        or _sha256(RECEIPT_DOMAIN + body) != root_fields[1]
    ):
        raise PublicBundleError("public bundle receipt root drifted")
    if values["repository"] != REPOSITORY:
        raise PublicBundleError("public bundle repository drifted")
    if not TAG_RE.fullmatch(values["release-tag"]):
        raise PublicBundleError("public bundle release tag is malformed")
    if values["source-commit"] != wp8q.TRACKED_COMMIT:
        raise PublicBundleError("public bundle commit lacks WP8Q protocol acceptance")
    expected_name = _asset_name(values["source-commit"])
    if values["asset-name"] != expected_name:
        raise PublicBundleError("public bundle asset name drifted")
    if values["asset-url"] != _asset_url(values["release-tag"], expected_name):
        raise PublicBundleError("public bundle locator is not canonical")
    if (
        not POSITIVE_RE.fullmatch(values["archive-bytes"])
        or int(values["archive-bytes"]) > MAX_ARCHIVE_BYTES
        or not HASH_RE.fullmatch(values["archive-sha256"])
        or any(not HASH_RE.fullmatch(values[key]) for key in (
            "bundle-root", "session-root", "host-attestation", "evidence-root"
        ))
        or values["public-reachability"] != "not-observed"
        or values["claim-status"] != "not-admitted"
    ):
        raise PublicBundleError("public bundle receipt identity drifted")
    return PublicationReceipt(
        values["repository"],
        values["release-tag"],
        values["asset-name"],
        values["asset-url"],
        int(values["archive-bytes"]),
        values["archive-sha256"],
        values["bundle-root"],
        values["session-root"],
        values["host-attestation"],
        values["source-commit"],
        values["evidence-root"],
        root_fields[1],
    )


def _tar_info(name: str, *, directory: bool, size: int = 0, mode: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.size = 0 if directory else size
    info.mode = mode
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def _archive_bytes(bundle: Path, replay: wp8n.Replay) -> tuple[str, bytes]:
    commit = replay.manifest.source_commit
    if commit != wp8q.TRACKED_COMMIT:
        raise PublicBundleError("paired bundle commit lacks WP8Q protocol acceptance")
    root_name = _asset_name(commit).removesuffix(".tar.gz")
    payloads = {}
    for relative in ARCHIVE_FILES:
        maximum = (
            wp8n.MAX_ARTIFACT_BYTES
            if relative.startswith("artifacts/")
            else wp8n.MAX_TEXT_BYTES
        )
        try:
            payloads[relative] = wp8n._read_regular(bundle / relative, relative, maximum)
        except wp8n.PairedEvidenceError as error:
            raise PublicBundleError(f"cannot package paired file: {relative}") from error
    raw_output = io.BytesIO()
    with gzip.GzipFile(
        fileobj=raw_output,
        mode="wb",
        filename="",
        mtime=0,
        compresslevel=9,
    ) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for relative in ARCHIVE_DIRECTORIES:
                name = root_name if not relative else f"{root_name}/{relative}"
                archive.addfile(_tar_info(name, directory=True, mode=0o700))
            for relative in ARCHIVE_FILES:
                payload = payloads[relative]
                mode = 0o700 if relative.startswith("artifacts/") else 0o600
                archive.addfile(
                    _tar_info(
                        f"{root_name}/{relative}",
                        directory=False,
                        size=len(payload),
                        mode=mode,
                    ),
                    io.BytesIO(payload),
                )
    raw = raw_output.getvalue()
    if not raw or len(raw) > MAX_ARCHIVE_BYTES:
        raise PublicBundleError("public bundle archive exceeds its bounded extent")
    return root_name, raw


def _archive_inventory(raw: bytes, receipt: PublicationReceipt) -> dict[str, bytes]:
    root_name = receipt.asset_name.removesuffix(".tar.gz")
    expected_names = tuple(
        root_name if not relative else f"{root_name}/{relative}"
        for relative in ARCHIVE_DIRECTORIES
    ) + tuple(f"{root_name}/{relative}" for relative in ARCHIVE_FILES)
    payloads: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            members = archive.getmembers()
            if tuple(member.name for member in members) != expected_names:
                raise PublicBundleError("public bundle archive inventory or order drifted")
            if archive.pax_headers:
                raise PublicBundleError("public bundle archive has global PAX metadata")
            for index, member in enumerate(members):
                is_directory = index < len(ARCHIVE_DIRECTORIES)
                expected_mode = 0o700 if is_directory or "/artifacts/" in member.name else 0o600
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.uname
                    or member.gname
                    or member.mtime != 0
                    or member.mode != expected_mode
                    or member.pax_headers
                    or (is_directory and (not member.isdir() or member.size != 0))
                    or (not is_directory and not member.isfile())
                ):
                    raise PublicBundleError(
                        f"public bundle member metadata drifted: {member.name}"
                    )
                if is_directory:
                    continue
                limit = (
                    wp8n.MAX_ARTIFACT_BYTES
                    if "/artifacts/" in member.name
                    else wp8n.MAX_TEXT_BYTES
                )
                if member.size <= 0 or member.size > limit:
                    raise PublicBundleError(
                        f"public bundle member extent is invalid: {member.name}"
                    )
                handle = archive.extractfile(member)
                if handle is None:
                    raise PublicBundleError(f"public bundle member is unreadable: {member.name}")
                payload = handle.read(limit + 1)
                if len(payload) != member.size:
                    raise PublicBundleError(f"public bundle member size drifted: {member.name}")
                relative = member.name[len(root_name) + 1 :]
                payloads[relative] = payload
                total += len(payload)
    except (OSError, EOFError, tarfile.TarError) as error:
        raise PublicBundleError("cannot decode public bundle archive") from error
    if total > MAX_UNCOMPRESSED_BYTES:
        raise PublicBundleError("public bundle uncompressed extent exceeds policy")
    return payloads


def _materialize_bundle(parent: Path, payloads: dict[str, bytes]) -> Path:
    bundle = parent / "bundle"
    bundle.mkdir(mode=0o700)
    for relative in ("artifacts", "artifacts/baseline", "artifacts/candidate"):
        (bundle / relative).mkdir(mode=0o700)
    for relative in ARCHIVE_FILES:
        mode = 0o700 if relative.startswith("artifacts/") else 0o600
        try:
            wp8n.wp8m.wp7c._write_regular(bundle / relative, payloads[relative], mode)
        except (KeyError, wp8n.wp8m.wp7c.RunnerError) as error:
            raise PublicBundleError(f"cannot materialize paired file: {relative}") from error
    return bundle


def _intake_report(
    admission: Admission,
    receipt: PublicationReceipt,
    replay: wp8n.Replay,
) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"receipt-root\t{receipt.root}",
        f"archive-sha256\t{receipt.archive_sha256}",
        f"bundle-root\t{replay.manifest.root}",
        f"session-root\t{replay.manifest.session_root}",
        f"host-attestation\t{replay.manifest.host_attestation}",
        f"source-commit\t{replay.manifest.source_commit}",
        f"evidence-root\t{replay.evidence_root}",
        "mode\texplicit-read-only-archive-replay",
        "archive-integrity\tverified",
        "locator-shape\tverified",
        "public-reachability\tnot-observed",
        "admission-status\tblocked",
        "claim-status\tnot-admitted",
        f"blockers\t{len(BLOCKERS)}",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def intake_archive(
    archive_path: Path,
    receipt_path: Path,
    admission: Admission,
) -> Intake:
    receipt = parse_receipt(receipt_path)
    if archive_path.name != receipt.asset_name:
        raise PublicBundleError("archive filename differs from public bundle receipt")
    try:
        raw = wp8n._read_regular(archive_path, "public bundle archive", MAX_ARCHIVE_BYTES)
    except wp8n.PairedEvidenceError as error:
        raise PublicBundleError("cannot read public bundle archive") from error
    if len(raw) != receipt.archive_bytes or _sha256(raw) != receipt.archive_sha256:
        raise PublicBundleError("public bundle archive size or SHA-256 drifted")
    payloads = _archive_inventory(raw, receipt)
    with tempfile.TemporaryDirectory(prefix="naux-s4-wp8r-intake-") as name:
        replay = wp8n.replay_bundle(
            _materialize_bundle(Path(name), payloads), admission.evidence
        )
    if (
        replay.manifest.root != receipt.bundle_root
        or replay.manifest.session_root != receipt.session_root
        or replay.manifest.host_attestation != receipt.host_attestation
        or replay.manifest.source_commit != receipt.source_commit
        or replay.evidence_root != receipt.evidence_root
    ):
        raise PublicBundleError("public receipt differs from replayed paired evidence")
    try:
        final = wp8n._read_regular(archive_path, "public bundle archive", MAX_ARCHIVE_BYTES)
    except wp8n.PairedEvidenceError as error:
        raise PublicBundleError("public bundle archive changed during intake") from error
    if len(final) != receipt.archive_bytes or _sha256(final) != receipt.archive_sha256:
        raise PublicBundleError("public bundle archive changed during intake")
    report, report_root = _intake_report(admission, receipt, replay)
    return Intake(receipt, replay, report, report_root)


def package_bundle(
    root: Path,
    bundle_path: Path,
    release_tag: str,
    output: Path,
    admission: Admission,
) -> tuple[bytes, str]:
    bundle = wp8n._bundle_directory(bundle_path)
    replay = wp8n.replay_bundle(bundle, admission.evidence)
    root_name, archive = _archive_bytes(bundle, replay)
    asset_name = f"{root_name}.tar.gz"
    receipt = _receipt_bytes(release_tag, asset_name, archive, replay)
    checked_output = wp8n.wp8m.wp7c._checked_output(root, output)
    stage = Path(tempfile.mkdtemp(prefix=f".{checked_output.name}.", dir=checked_output.parent))
    published = False
    try:
        wp8n.wp8m.wp7c._write_regular(stage / asset_name, archive)
        receipt_name = f"{asset_name}.receipt.tsv"
        wp8n.wp8m.wp7c._write_regular(stage / receipt_name, receipt)
        intake_archive(stage / asset_name, stage / receipt_name, admission)
        directory = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        wp8n.wp8m.wp7c._rename_noreplace(stage, checked_output)
        published = True
        parent = os.open(checked_output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if not published:
            shutil.rmtree(stage, ignore_errors=True)
    parsed = parse_receipt(checked_output / f"{asset_name}.receipt.tsv")
    rows = (
        REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"receipt-root\t{parsed.root}",
        f"archive-sha256\t{parsed.archive_sha256}",
        f"bundle-root\t{parsed.bundle_root}",
        f"source-commit\t{parsed.source_commit}",
        "mode\texplicit-local-deterministic-archive",
        "archive-integrity\tverified",
        "public-reachability\tnot-observed",
        "admission-status\tblocked",
        "claim-status\tnot-admitted",
        f"blockers\t{len(BLOCKERS)}",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    report_root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{report_root}\n".encode(), report_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--package-bundle", type=Path)
    parser.add_argument("--release-tag")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--receipt", type=Path)
    arguments = parser.parse_args(argv)
    package_values = (arguments.package_bundle, arguments.release_tag, arguments.output)
    intake_values = (arguments.archive, arguments.receipt)
    if any(value is not None for value in package_values) and not all(
        value is not None for value in package_values
    ):
        parser.error("packaging requires --package-bundle, --release-tag, and --output")
    if any(value is not None for value in intake_values) and not all(
        value is not None for value in intake_values
    ):
        parser.error("intake requires --archive and --receipt")
    if all(value is not None for value in package_values) and all(
        value is not None for value in intake_values
    ):
        parser.error("packaging and intake modes are mutually exclusive")
    try:
        admission = validate(arguments.root)
        if arguments.package_bundle is not None:
            report, _root = package_bundle(
                arguments.root.resolve(strict=True),
                arguments.package_bundle,
                arguments.release_tag,
                arguments.output,
                admission,
            )
            sys.stdout.buffer.write(report)
        elif arguments.archive is not None:
            sys.stdout.buffer.write(
                intake_archive(arguments.archive, arguments.receipt, admission).report
            )
        else:
            sys.stdout.buffer.write(admission.report)
        return 0
    except (
        PublicBundleError,
        wp8q.PublicProtocolError,
        wp8q.wp8p.ClaimAdmissionError,
        wp8n.PairedEvidenceError,
        wp8n.wp8m.PairedRunnerError,
        wp8n.wp8m.wp7c.RunnerError,
        OSError,
        ValueError,
    ) as error:
        print(f"S4-WP8R validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
