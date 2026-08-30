#!/usr/bin/env python3
"""Admit the exact WP8G artifacts to an isolated untimed candidate role."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import license_transition as lt1
import s4_register_residency_process as wp8g
import s4_residual_role_admission as wp5f


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-ROLE\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-ROLE-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-ROLE-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-role:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-role:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-role:report:v1\0"
CONTRACT_SEAL = "387ef6a1385363ec1ceb260851c0c606e1410d5962bc99d76cb99904cc75bd5f"
WP5F_CONTRACT_SEAL = "9e2b2b0ff2514ec084d4b6f53f15477a69849cf53ba2343aa6f5f1485ac056f5"
WP5F_AUTHORITY_SEAL = "1d85ad923f5db2eb520cee9d3582bbc97f63b711c67d5d4b44d5859fb0fa92bd"
LT1_AUTHORITY_SEAL = "225cda9b967bd6c0bf93330721bfed1d41841fce11cc7e2677b4885678e5d5be"
WP8G_CONTRACT_SEAL = "050107eff2a80a6dc6a4af0f9d2c64eedae8732dafa038e430bfab9303cc03bb"
WP8G_AUTHORITY_SEAL = "930c22a75eafb7c36255389f99e219fc46c9f82fd529c5665c1cd086a42caa77"
WP8G_REPLAY_ROOT = "5d0c6e359b4397bee04645235ba97a0ca3f1a83ab81692ef5009767df180b45f"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")
MAX_TEXT_BYTES = 1_000_000

METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-baseline-role-authority", WP5F_AUTHORITY_SEAL),
    ("parent-license-transition-authority", LT1_AUTHORITY_SEAL),
    ("parent-candidate-process-contract", WP8G_CONTRACT_SEAL),
    ("parent-candidate-process-authority", WP8G_AUTHORITY_SEAL),
    ("role-status", "untimed-register-residency-candidate-admitted"),
    ("claim-status", "untimed-candidate-role-only"),
    ("timing-status", "forbidden"),
    ("required-role", "naux-register-residency-candidate"),
    ("baseline-role", "naux-residual"),
    ("role-isolation", "does-not-replace-wp5f"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("dataset", "static-n16384-r50"),
    ("artifact", "linker-free-standalone-elf64"),
    ("frontend", "ordinary-naux-frontend"),
    ("transform", "one-hot-inner-loop-index-r12-residency"),
    ("runtime-envelope", "no-vm-jit-libc-system-linker"),
    ("artifact-count", "4"),
    ("replay-count", "2"),
)
AUTHORITIES = (
    ("01", "baseline-role", WP5F_AUTHORITY_SEAL),
    ("02", "license-transition", LT1_AUTHORITY_SEAL),
    ("03", "candidate-process", WP8G_AUTHORITY_SEAL),
)
GATES = (
    ("01", "license-transition", "closed", "exact-apache-authority-bridge"),
    ("02", "baseline-role", "closed", "exact-wp5f-retained"),
    ("03", "candidate-process", "closed", "exact-wp8g-artifacts"),
    ("04", "workload-identity", "closed", "same-four-oracles-and-work-hashes"),
    ("05", "work-preservation", "closed", "terminal-register-and-frame-state"),
    ("06", "artifact-sovereignty", "closed", "no-vm-jit-libc-system-linker"),
    ("07", "fresh-process-parity", "closed", "four-exact-results-two-passes-no-fallback"),
    ("08", "independent-replay", "closed", "candidate-target-process-elf-result"),
    ("09", "role-isolation", "closed", "baseline-remains-authoritative"),
)
CLOSURES = (("01", "candidate-role-unavailable", "closed", "wp8h-composition-authority"),)
ARTIFACTS = (
    (1, "sum-dense", 6_710_476_800, "5594c78b156929f021990ba06ebc045d17316f2c45b432a1009f210f6b985cac", "d8a2ff6b4e4e91d8c98c634fecaaa53f9bb5955ae8dc9d75825382bfd872aba5", "c13f847f443403baf6d3152122b2f8f9bd52dd60b8c740247be5e703530700f8"),
    (2, "branch-mix", -69_189_632, "1f188884b4bb04d85dc00608cf436c6b07d8a665d17f63d7d8ab8192749ba195", "897defb6998bc6c95c5e60b48fce2415edbf54e9e8c939bf7728e7f0db4ea870", "cf31d1407677213a85ba3dbb395a06895e8c5c63dce46a42ac13fe916769f0a7"),
    (3, "dot-product", 73_294_064_435_200, "62291dc2f6662fdcb8f0a0e0d6f04a8a6f31ce498e6572a5908602b1ed7f2f7f", "0171b94556cb4ab82805171c84f09975b678ce91b4321d69dc851ce704800964", "b33c2f464595c9c07e6482288917874e22e271296f428d535ddcda15ba8d6846"),
    (4, "list-update", 6_730_547_200, "a7937fa3e64d75cf6a96165d0e63baa4a0dc66b365647af8a87b3ea07079dc55", "8114b4c85fe5b3062645aaf625342715f5d170f6f0acda6834ae66c22707306a", "18cd00a4b3f4b43c300b6643e248574c8f956ad52971915997d0482ba2c351cd"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8H"),
    ("authority-id", "s4-register-residency-candidate-role-v1"),
    ("role-status", "untimed-register-residency-candidate-admitted"),
    ("claim-status", "untimed-candidate-role-only"),
    ("timing-status", "forbidden"),
    ("kernel-count", "4"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-role.yml",
    "distribution/s4-performance/WP8H-CANDIDATE-ROLE.tsv",
    "distribution/s4-performance/WP8H-NONCLAIMS.md",
    "distribution/s4-performance/WP8H-README.md",
    "scripts/s4_register_residency_role.py",
    "scripts/tests/test_s4_register_residency_role.py",
    "scripts/tests/test_s4_register_residency_role_static.py",
)


class CandidateRoleError(RuntimeError):
    """A fail-closed WP8H composition or replay error."""


@dataclass(frozen=True)
class ArtifactRecord:
    ordinal: int
    name: str
    oracle: int
    work_hash: str
    target_hash: str
    elf_hash: str


@dataclass(frozen=True)
class Contract:
    artifacts: tuple[ArtifactRecord, ...]
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
    process: wp8g.Admission
    static_report: bytes
    static_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_regular(path: Path, label: str) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size > MAX_TEXT_BYTES:
        raise CandidateRoleError(f"{label} is not a bounded regular file")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        raw = handle.read(MAX_TEXT_BYTES + 1)
        after = os.fstat(handle.fileno())
    rebound = path.lstat()
    if (
        (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        or (opened.st_dev, opened.st_ino, opened.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or len(raw) != after.st_size
        or stat.S_ISLNK(rebound.st_mode)
        or (rebound.st_dev, rebound.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise CandidateRoleError(f"{label} changed while read")
    return raw


def _canonical(raw: bytes, label: str) -> list[str]:
    if not raw or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise CandidateRoleError(f"{label} has invalid canonical extent")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise CandidateRoleError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise CandidateRoleError(f"{label} contains blank or padded rows")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    raw = _read_regular(path, path.name)
    lines = _canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise CandidateRoleError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]) or _sha256(domain + body) != fields[1]:
        raise CandidateRoleError(f"{path.name} seal drifted")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL:
        raise CandidateRoleError("WP8H contract identity drifted")
    expected = [f"meta\t{key}\t{value}" for key, value in METADATA]
    expected.extend(f"authority\t{ordinal}\t{name}\t{value}" for ordinal, name, value in AUTHORITIES)
    expected.extend(f"gate\t{ordinal}\t{name}\t{status}\t{detail}" for ordinal, name, status, detail in GATES)
    expected.extend(f"artifact\t{ordinal:02}\t{name}\t{oracle}\t{work}\t{target}\t{elf}" for ordinal, name, oracle, work, target, elf in ARTIFACTS)
    expected.extend(f"closure\t{ordinal}\t{name}\t{status}\t{detail}" for ordinal, name, status, detail in CLOSURES)
    if rows != expected:
        raise CandidateRoleError("WP8H contract rows drifted")
    return Contract(tuple(ArtifactRecord(*row) for row in ARTIFACTS), seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    prefix = [f"meta\t{key}\t{value}" for key, value in AUTHORITY_METADATA]
    prefix.extend(
        (
            f"component\tcandidate-role-contract\tdistribution/s4-performance/WP8H-CANDIDATE-ROLE.tsv\t{contract_seal}",
            f"parent\tbaseline-role-authority\tdistribution/s4-performance/WP5F-AUTHORITY.tsv\t{WP5F_AUTHORITY_SEAL}",
            f"parent\tlicense-transition-authority\tdistribution/license-transition/LT1-AUTHORITY.tsv\t{LT1_AUTHORITY_SEAL}",
            f"parent\tcandidate-process-authority\tdistribution/s4-performance/WP8G-AUTHORITY.tsv\t{WP8G_AUTHORITY_SEAL}",
        )
    )
    if rows[: len(prefix)] != prefix:
        raise CandidateRoleError("WP8H authority metadata or parent binding drifted")
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
            or fields[5] != "candidate-role"
        ):
            raise CandidateRoleError("WP8H authority file row is malformed")
        records.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise CandidateRoleError("WP8H authority inventory drifted")
    return Authority(tuple(records), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        raw = _read_regular(path, record.path)
        if (
            stat.S_IFREG | stat.S_IMODE(path.lstat().st_mode) != record.mode
            or len(raw) != record.size
            or _sha256(raw) != record.sha256
        ):
            raise CandidateRoleError(f"bound WP8H file drifted: {record.path}")


def _verify_composition(root: Path, contract: Contract, process: wp8g.Admission) -> None:
    if process.contract.seal != WP8G_CONTRACT_SEAL or process.authority.seal != WP8G_AUTHORITY_SEAL:
        raise CandidateRoleError("WP8G parent identity drifted")
    transition = lt1.validate(root)
    if transition.authority.seal != LT1_AUTHORITY_SEAL:
        raise CandidateRoleError("Apache transition authority drifted")
    baseline_contract = wp5f.parse_contract(root / "distribution/s4-performance/WP5F-ROLE.tsv")
    baseline_authority = wp5f.parse_authority(
        root / "distribution/s4-performance/WP5F-AUTHORITY.tsv", baseline_contract.seal
    )
    if baseline_contract.seal != WP5F_CONTRACT_SEAL or baseline_authority.seal != WP5F_AUTHORITY_SEAL:
        raise CandidateRoleError("WP5F historical baseline identity drifted")
    expected_candidate = tuple(
        ArtifactRecord(record.ordinal, record.name, record.oracle, record.work_hash, record.process_hash, record.elf_hash)
        for record in process.contract.records
    )
    if contract.artifacts != expected_candidate:
        raise CandidateRoleError("WP8H artifacts differ from the WP8G process contract")
    baseline_work = tuple((record.ordinal, record.name, record.oracle, record.work_hash) for record in baseline_contract.artifacts)
    candidate_work = tuple((record.ordinal, record.name, record.oracle, record.work_hash) for record in contract.artifacts)
    if baseline_work != candidate_work:
        raise CandidateRoleError("candidate workload differs from the retained WP5F baseline")
    if any(
        candidate.target_hash == baseline.target_hash or candidate.elf_hash == baseline.elf_hash
        for candidate, baseline in zip(contract.artifacts, baseline_contract.artifacts)
    ):
        raise CandidateRoleError("candidate role aliases a WP5F baseline artifact")


def _verify_source_boundary(root: Path) -> None:
    workflow = _read_regular(
        root / ".github/workflows/s4-register-residency-role.yml", "WP8H workflow"
    ).decode()
    required = (
        "scripts/license_transition.py",
        "cargo build --locked -p naux --example naux_s4_register_residency_process",
        "scripts/s4_register_residency_role.py",
        "test_s4_register_residency_role_static",
        "test_s4_register_residency_role",
    )
    if any(token not in workflow for token in required):
        raise CandidateRoleError("WP8H workflow omits a required gate")
    source = _read_regular(root / "scripts/s4_register_residency_role.py", "WP8H validator").decode().lower()
    forbidden = (
        "import" + " time",
        "perf" + "_counter",
        "monotonic" + "_ns",
        "time" + "_ns",
        "runtime" + "_ns",
        "through" + "put",
        "lat" + "ency",
        "speed" + "up",
    )
    if any(token in source for token in forbidden):
        raise CandidateRoleError("WP8H validator crossed its no-measurement boundary")
    expected = {
        "WP8H-AUTHORITY.tsv",
        "WP8H-CANDIDATE-ROLE.tsv",
        "WP8H-NONCLAIMS.md",
        "WP8H-README.md",
    }
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP8H-*")
        if path.is_file()
    }
    if actual != expected:
        raise CandidateRoleError("unexpected WP8H distribution artifact")


def _report(
    contract: Contract,
    authority: Authority,
    results: tuple[wp8g.ProcessResult, ...] = (),
    process_report: bytes | None = None,
) -> bytes:
    replayed = process_report is not None
    rows = [
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"baseline-role-authority\t{WP5F_AUTHORITY_SEAL}",
        f"license-transition-authority\t{LT1_AUTHORITY_SEAL}",
        f"candidate-process-authority\t{WP8G_AUTHORITY_SEAL}",
        f"role-status\t{'untimed-register-residency-candidate-admitted' if replayed else 'pending-process-replay'}",
        "claim-status\tuntimed-candidate-role-only",
        "timing-status\tforbidden",
        "role\tnaux-register-residency-candidate",
        "baseline-role\tnaux-residual",
        "role-isolation\tdoes-not-replace-wp5f",
        f"mode\t{'untimed-candidate-role-replay' if replayed else 'static-authority'}",
        "kernels\t4",
        f"replays\t{2 if replayed else 0}",
        "gates\t9",
        "closed-blockers\t1",
    ]
    if process_report is not None:
        process_root = process_report.decode().split("report-root\t", 1)[1].strip()
        rows.append(f"process-report-root\t{process_root}")
        rows.extend(
            f"result\t{result.pass_number}\t{result.ordinal:02}\t{result.name}\t"
            f"{result.checksum}\t{result.outer}\t{result.inner}\t{result.owner}"
            for result in results
        )
    body = b"".join(f"{row}\n".encode() for row in rows)
    return body + f"report-root\t{_sha256(REPORT_DOMAIN + body)}\n".encode()


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    contract = parse_contract(root / "distribution/s4-performance/WP8H-CANDIDATE-ROLE.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP8H-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    process = wp8g.validate(root)
    _verify_composition(root, contract, process)
    _verify_source_boundary(root)
    report = _report(contract, authority)
    report_root = report.decode().split("report-root\t", 1)[1].strip()
    return Admission(contract, authority, process, report, report_root)


def replay(
    admission: Admission, binary: Path
) -> tuple[bytes, tuple[wp8g.ProcessResult, ...]]:
    process_report, candidate, results = wp8g.replay(admission.process, binary)
    process_root = process_report.decode().split("report-root\t", 1)[1].strip()
    if process_root != WP8G_REPLAY_ROOT:
        raise CandidateRoleError("WP8G replay root drifted")
    actual = tuple(
        ArtifactRecord(
            kernel.record.ordinal,
            kernel.record.name,
            kernel.record.oracle,
            kernel.record.work_hash,
            kernel.record.process_hash,
            kernel.record.elf_hash,
        )
        for kernel in candidate.kernels
    )
    if actual != admission.contract.artifacts or len(results) != 8:
        raise CandidateRoleError("replayed artifact set differs from the admitted candidate role")
    expected_order = tuple((pass_number, ordinal) for pass_number in (1, 2) for ordinal in (1, 2, 3, 4))
    if tuple((result.pass_number, result.ordinal) for result in results) != expected_order:
        raise CandidateRoleError("candidate-role replay order or coverage drifted")
    return _report(admission.contract, admission.authority, results, process_report), results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--binary", type=Path)
    arguments = parser.parse_args()
    try:
        admission = validate(arguments.root)
        if arguments.binary is None:
            sys.stdout.buffer.write(admission.static_report)
        else:
            report, _ = replay(admission, arguments.binary)
            sys.stdout.buffer.write(report)
    except (
        CandidateRoleError,
        wp8g.ProcessReplayError,
        wp8g.wp8f.ElfAuthorityError,
        wp5f.RoleAdmissionError,
        lt1.TransitionError,
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
    ) as error:
        print(f"S4-WP8H validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
