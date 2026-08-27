#!/usr/bin/env python3
"""Admit the exact S4 residual artifacts to an untimed comparison role."""

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

import s4_residual_process as wp5e


CONTRACT_MAGIC = "NAUX-S4-RESIDUAL-ROLE-ADMISSION\t1"
AUTHORITY_MAGIC = "NAUX-S4-RESIDUAL-ROLE-ADMISSION-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-RESIDUAL-ROLE-ADMISSION-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-residual-role-admission:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-residual-role-admission:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-residual-role-admission:report:v1\0"
WP5_ROLE_CONTRACT_SEAL = "dca95743972986a51096dee608b3112171397addefd0137aa0a6133f8657199b"
WP5_ROLE_AUTHORITY_SEAL = "93353f2d40cb1217b4b37a30f04c9807ecde9d98d7e4e370a99286fbe355bf5d"
WP5E_CONTRACT_SEAL = "213eb3f1c9c596141ca6d6793368e85e901d308e2c57d93f0917ce766e63c8e8"
WP5E_AUTHORITY_SEAL = "098a7cb2216359c03ab1e58d3a41f6c904d411ccafa1c10b0a88885fc3dfc53f"
WP5E_REPLAY_ROOT = "325f518cd65e3a95c750094efaa2fdd279414db1915c9ea7620d61a468654a3f"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-role-contract", WP5_ROLE_CONTRACT_SEAL),
    ("parent-role-authority", WP5_ROLE_AUTHORITY_SEAL),
    ("parent-process-contract", WP5E_CONTRACT_SEAL),
    ("parent-process-authority", WP5E_AUTHORITY_SEAL),
    ("role-status", "untimed-naux-residual-admitted"),
    ("claim-status", "untimed-role-only"),
    ("timing-status", "forbidden"),
    ("required-role", "naux-residual"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("dataset", "static-n16384-r50"),
    ("artifact", "linker-free-standalone-elf64"),
    ("frontend", "ordinary-naux-frontend"),
    ("generator", "single-general-pipeline"),
    ("runtime-envelope", "no-vm-jit-libc-system-linker"),
    ("artifact-count", "4"),
    ("replay-count", "2"),
)
CONTRACT_AUTHORITIES = (
    ("01", "benchmark", "b23533c4e96ec9e3b66482e96b79fdeb5985c823ce012d827e69eb1c14a4b659"),
    ("02", "reference", "0361c1e0d90bc3ba8d9a1e0bead7466bd71be3e3a723d605606730144ae7db6a"),
    ("03", "native-carrier", "7a853a68da91a4d41f3fe6f7b9e9e21dd254a4d4ac36b248007e506bd046c9ab"),
    ("04", "measurement-boundary", "bda4409f32e1afe162b68401529d127cf4a77077df000826823d2660ee4ade26"),
    ("05", "residual-role-contract", WP5_ROLE_AUTHORITY_SEAL),
    ("06", "specialization-request", "e86fa78b86865b389493a6f8cf4abae5acd8403c6413ec14d04ecb61eeef8d9e"),
    ("07", "structural-residual", "f41ed069566b2017aae0cce074df6f2b4d3aba3b1402e0bc50da285a62fb9cc7"),
    ("08", "residual-machine-ir", "bcb4aab033397092049e9fcaf32aba9e615d3029789dafdc2dfb32ea3324860f"),
    ("09", "residual-elf64", "eba915d65c448d0251c4b253c911d61e2f06b8d4bcc4cf3e57a7eea78bd87fb4"),
    ("10", "residual-process", WP5E_AUTHORITY_SEAL),
)
CONTRACT_GATES = (
    ("01", "parent-authorities", "closed", "exact-wp1-through-wp5e"),
    ("02", "source-identity", "closed", "ordinary-frontend-no-benchmark-parser"),
    ("03", "specialization", "closed", "explicit-sealed-n-and-reps"),
    ("04", "work-preservation", "closed", "sealed-structure-plus-terminal-frame-state"),
    ("05", "generator-generality", "closed", "one-pipeline-four-kernels"),
    ("06", "artifact-sovereignty", "closed", "no-vm-jit-libc-system-linker"),
    ("07", "fresh-process-parity", "closed", "four-exact-results-two-passes-no-fallback"),
    ("08", "independent-replay", "closed", "source-residual-plan-bytes-elf-result"),
)
CONTRACT_CLOSURES = (
    ("01", "residual-generator-unavailable", "closed", "wp5b-through-wp5e"),
    ("02", "four-artifact-replay-unavailable", "closed", "wp5e-eight-exact-process-results"),
    ("03", "untimed-role-admission-unavailable", "closed", "wp5f-composition-authority"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP5F"),
    ("authority-id", "s4-residual-role-admission-v1"),
    ("role-status", "untimed-naux-residual-admitted"),
    ("claim-status", "untimed-role-only"),
    ("timing-status", "forbidden"),
    ("kernel-count", "4"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-residual-role-admission.yml",
    "distribution/s4-performance/WP5F-NONCLAIMS.md",
    "distribution/s4-performance/WP5F-README.md",
    "distribution/s4-performance/WP5F-ROLE.tsv",
    "scripts/s4_residual_role_admission.py",
    "scripts/tests/test_s4_residual_role_admission.py",
    "scripts/tests/test_s4_residual_role_admission_static.py",
)
AUTHORITY_PATHS = (
    "distribution/s4-performance/AUTHORITY.tsv",
    "distribution/s4-performance/WP2-AUTHORITY.tsv",
    "distribution/s4-performance/WP3-AUTHORITY.tsv",
    "distribution/s4-performance/WP4-AUTHORITY.tsv",
    "distribution/s4-performance/WP5-AUTHORITY.tsv",
    "distribution/s4-performance/WP5A-AUTHORITY.tsv",
    "distribution/s4-performance/WP5B-AUTHORITY.tsv",
    "distribution/s4-performance/WP5C-AUTHORITY.tsv",
    "distribution/s4-performance/WP5D-AUTHORITY.tsv",
    "distribution/s4-performance/WP5E-AUTHORITY.tsv",
)


class RoleAdmissionError(RuntimeError):
    """A fail-closed S4-WP5F role-admission error."""


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
    parent: wp5e.Admission
    static_report: bytes
    static_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(raw: bytes, label: str, maximum: int = 131_072) -> list[str]:
    if not raw or len(raw) > maximum or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise RoleAdmissionError(f"{label} has invalid extent or encoding")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RoleAdmissionError(f"{label} is not UTF-8") from error
    lines = text.splitlines()
    if any(not line for line in lines):
        raise RoleAdmissionError(f"{label} contains a blank row")
    return lines


def _sealed_lines(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RoleAdmissionError(f"{path.name} is not a regular file")
    raw = path.read_bytes()
    lines = _canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise RoleAdmissionError(f"{path.name} shape or magic drifted")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise RoleAdmissionError(f"{path.name} seal row is malformed")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if _sha256(domain + body) != fields[1]:
        raise RoleAdmissionError(f"{path.name} seal verification failed")
    return lines, fields[1]


def parse_contract(path: Path) -> Contract:
    lines, seal = _sealed_lines(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    index = 1
    metadata: list[tuple[str, str]] = []
    while index < len(lines) - 1 and lines[index].startswith("meta\t"):
        fields = lines[index].split("\t")
        if len(fields) != 3:
            raise RoleAdmissionError("WP5F contract metadata is malformed")
        metadata.append((fields[1], fields[2]))
        index += 1
    if tuple(metadata) != CONTRACT_METADATA:
        raise RoleAdmissionError("WP5F contract metadata drifted")

    authorities: list[tuple[str, str, str]] = []
    while index < len(lines) - 1 and lines[index].startswith("authority\t"):
        fields = lines[index].split("\t")
        if len(fields) != 4 or not HASH_RE.fullmatch(fields[3]):
            raise RoleAdmissionError("WP5F authority-chain row is malformed")
        authorities.append((fields[1], fields[2], fields[3]))
        index += 1
    if tuple(authorities) != CONTRACT_AUTHORITIES:
        raise RoleAdmissionError("WP5F authority chain drifted")

    gates: list[tuple[str, str, str, str]] = []
    while index < len(lines) - 1 and lines[index].startswith("gate\t"):
        fields = lines[index].split("\t")
        if len(fields) != 5:
            raise RoleAdmissionError("WP5F gate row is malformed")
        gates.append((fields[1], fields[2], fields[3], fields[4]))
        index += 1
    if tuple(gates) != CONTRACT_GATES:
        raise RoleAdmissionError("WP5F gate set drifted")

    artifacts: list[ArtifactRecord] = []
    while index < len(lines) - 1 and lines[index].startswith("artifact\t"):
        fields = lines[index].split("\t")
        if (
            len(fields) != 7
            or fields[1] != f"{len(artifacts) + 1:02}"
            or not INT_RE.fullmatch(fields[3])
            or any(not HASH_RE.fullmatch(value) for value in fields[4:])
        ):
            raise RoleAdmissionError("WP5F artifact row is malformed")
        artifacts.append(
            ArtifactRecord(int(fields[1]), fields[2], int(fields[3]), fields[4], fields[5], fields[6])
        )
        index += 1

    closures: list[tuple[str, str, str, str]] = []
    while index < len(lines) - 1 and lines[index].startswith("closure\t"):
        fields = lines[index].split("\t")
        if len(fields) != 5:
            raise RoleAdmissionError("WP5F closure row is malformed")
        closures.append((fields[1], fields[2], fields[3], fields[4]))
        index += 1
    if tuple(closures) != CONTRACT_CLOSURES or index != len(lines) - 1:
        raise RoleAdmissionError("WP5F closure set or row extent drifted")
    if len(artifacts) != 4 or tuple(record.ordinal for record in artifacts) != (1, 2, 3, 4):
        raise RoleAdmissionError("WP5F artifact order or count drifted")
    return Contract(tuple(artifacts), seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed_lines(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    index = 1
    metadata: list[tuple[str, str]] = []
    while index < len(lines) - 1 and lines[index].startswith("meta\t"):
        fields = lines[index].split("\t")
        if len(fields) != 3:
            raise RoleAdmissionError("WP5F authority metadata is malformed")
        metadata.append((fields[1], fields[2]))
        index += 1
    if tuple(metadata) != AUTHORITY_METADATA:
        raise RoleAdmissionError("WP5F authority metadata drifted")
    expected_links = (
        f"component\trole-admission-contract\tdistribution/s4-performance/WP5F-ROLE.tsv\t{contract_seal}",
        f"parent\tresidual-role-authority\tdistribution/s4-performance/WP5-AUTHORITY.tsv\t{WP5_ROLE_AUTHORITY_SEAL}",
        f"parent\tresidual-process-authority\tdistribution/s4-performance/WP5E-AUTHORITY.tsv\t{WP5E_AUTHORITY_SEAL}",
    )
    if tuple(lines[index : index + 3]) != expected_links:
        raise RoleAdmissionError("WP5F component or parent binding drifted")
    index += 3
    files: list[FileRecord] = []
    while index < len(lines) - 1:
        fields = lines[index].split("\t")
        if (
            len(fields) != 6
            or fields[0] != "file"
            or not MODE_RE.fullmatch(fields[1])
            or not UINT_RE.fullmatch(fields[2])
            or not HASH_RE.fullmatch(fields[3])
            or not PATH_RE.fullmatch(fields[4])
            or fields[5] != "role-admission"
        ):
            raise RoleAdmissionError("WP5F authority file row is malformed")
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
        index += 1
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise RoleAdmissionError("WP5F authority file inventory drifted")
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise RoleAdmissionError(f"WP5F bound file is not regular: {record.path}")
        raw = path.read_bytes()
        mode = stat.S_IFREG | stat.S_IMODE(metadata.st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise RoleAdmissionError(f"WP5F bound file drifted: {record.path}")


def _terminal_seal(path: Path) -> str:
    lines = _canonical(path.read_bytes(), path.name)
    fields = lines[-1].split("\t")
    if len(fields) != 2 or fields[0] != "seal" or not HASH_RE.fullmatch(fields[1]):
        raise RoleAdmissionError(f"authority seal row drifted: {path.name}")
    return fields[1]


def _verify_chain(root: Path) -> None:
    actual = tuple(_terminal_seal(root / path) for path in AUTHORITY_PATHS)
    expected = tuple(seal for _, _, seal in CONTRACT_AUTHORITIES)
    if actual != expected:
        raise RoleAdmissionError("WP1-WP5E authority identity chain drifted")


def _verify_contract_composition(
    contract: Contract,
    parent: wp5e.Admission,
    role_contract: object,
) -> None:
    if parent.contract.seal != WP5E_CONTRACT_SEAL or parent.authority.seal != WP5E_AUTHORITY_SEAL:
        raise RoleAdmissionError("WP5E parent identity drifted")
    if getattr(role_contract, "seal", None) != WP5_ROLE_CONTRACT_SEAL:
        raise RoleAdmissionError("original WP5 role contract drifted")
    expected = tuple(
        ArtifactRecord(
            record.ordinal,
            record.name,
            record.oracle,
            record.work_hash,
            record.process_target_hash,
            record.elf_hash,
        )
        for record in parent.contract.records
    )
    if contract.artifacts != expected:
        raise RoleAdmissionError("WP5F artifacts differ from the WP5E process contract")
    blockers = tuple(name for _, name in getattr(role_contract, "blockers"))
    closures = tuple(name for _, name, _, _ in CONTRACT_CLOSURES)
    if blockers != closures:
        raise RoleAdmissionError("WP5F does not close the exact WP5 blocker set")


def _verify_source_boundary(root: Path) -> None:
    workflow = (root / ".github/workflows/s4-residual-role-admission.yml").read_text()
    required = (
        "cargo test --locked -p naux --example naux_s4_residual_process",
        "cargo build --locked -p naux --example naux_s4_residual_process",
        "scripts/s4_residual_role_admission.py",
        "test_s4_residual_role_admission",
    )
    if any(token not in workflow for token in required):
        raise RoleAdmissionError("WP5F workflow omits a required replay gate")
    source = (root / "scripts/s4_residual_role_admission.py").read_text().lower()
    forbidden_clock_tokens = (
        "import" + " time",
        "perf" + "_counter",
        "monotonic" + "_ns",
        "time" + "_ns",
        "runtime" + "_ns",
    )
    for token in forbidden_clock_tokens:
        if token in source:
            raise RoleAdmissionError(f"clock token entered WP5F: {token}")
    expected = {"WP5F-AUTHORITY.tsv", "WP5F-NONCLAIMS.md", "WP5F-README.md", "WP5F-ROLE.tsv"}
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP5F-*")
        if path.is_file()
    }
    if actual != expected:
        raise RoleAdmissionError("unexpected WP5F distribution artifact")


def _report(
    contract: Contract,
    authority: Authority,
    results: tuple[wp5e.ProcessResult, ...] = (),
    process_report: bytes | None = None,
) -> bytes:
    replayed = process_report is not None
    rows = [
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"parent-role-authority\t{WP5_ROLE_AUTHORITY_SEAL}",
        f"parent-process-authority\t{WP5E_AUTHORITY_SEAL}",
        f"role-status\t{'untimed-naux-residual-admitted' if replayed else 'pending-process-replay'}",
        "claim-status\tuntimed-role-only",
        "timing-status\tforbidden",
        "role\tnaux-residual",
        f"mode\t{'untimed-role-replay' if replayed else 'static-authority'}",
        "kernels\t4",
        f"replays\t{2 if replayed else 0}",
        "gates\t8",
        "closed-blockers\t3",
    ]
    if process_report is not None:
        process_root = process_report.decode().split("report-root\t", 1)[1].strip()
        rows.append(f"process-report-root\t{process_root}")
        for result in results:
            rows.append(
                f"result\t{result.pass_number}\t{result.ordinal:02}\t{result.name}\t"
                f"{result.checksum}\t{result.outer}\t{result.inner}\t{result.owner}"
            )
    body = b"".join(f"{row}\n".encode() for row in rows)
    return body + f"report-root\t{_sha256(REPORT_DOMAIN + body)}\n".encode()


def validate(root: Path) -> Admission:
    root = root.resolve()
    parent = wp5e.validate(root)
    role = wp5e.wp5d.wp5c.wp5b.wp5a.wp5.validate(root)
    contract = parse_contract(root / "distribution/s4-performance/WP5F-ROLE.tsv")
    _verify_chain(root)
    _verify_contract_composition(contract, parent, role.contract)
    authority = parse_authority(
        root / "distribution/s4-performance/WP5F-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_source_boundary(root)
    report = _report(contract, authority)
    report_root = report.decode().split("report-root\t", 1)[1].strip()
    return Admission(contract, authority, parent, report, report_root)


def replay(admission: Admission, binary: Path) -> tuple[bytes, tuple[wp5e.ProcessResult, ...]]:
    process_report, candidate, results = wp5e.replay(admission.parent, binary)
    process_root = process_report.decode().split("report-root\t", 1)[1].strip()
    if process_root != WP5E_REPLAY_ROOT:
        raise RoleAdmissionError("WP5E replay root drifted")
    actual = tuple(
        (kernel.record.ordinal, kernel.record.name, kernel.record.process_target_hash, kernel.record.elf_hash)
        for kernel in candidate.kernels
    )
    expected = tuple(
        (record.ordinal, record.name, record.target_hash, record.elf_hash)
        for record in admission.contract.artifacts
    )
    if actual != expected or len(results) != 8:
        raise RoleAdmissionError("replayed artifact set differs from the admitted role")
    for pass_number in (1, 2):
        observed = tuple(result for result in results if result.pass_number == pass_number)
        if tuple(result.ordinal for result in observed) != (1, 2, 3, 4):
            raise RoleAdmissionError("role replay order or coverage drifted")
    return _report(admission.contract, admission.authority, results, process_report), results


def main() -> int:
    parser = argparse.ArgumentParser()
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
        RoleAdmissionError,
        wp5e.ProcessReplayError,
        wp5e.wp5d.Elf64Error,
        OSError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"S4-WP5F validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
