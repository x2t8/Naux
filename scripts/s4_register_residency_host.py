#!/usr/bin/env python3
"""Admit the WP8H candidate to the clock-free WP6 host protocol."""

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
import s4_controlled_host as wp6
import s4_register_residency_role as wp8h


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-HOST-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-HOST-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-HOST-REPORT\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-host:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-host:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-host:report:v1\0"
CONTRACT_SEAL = "1da0e075623f18bed18f2ef3df464a152d1facf45c0a16f5e98d23c216d3f441"
LT1_AUTHORITY_SEAL = "225cda9b967bd6c0bf93330721bfed1d41841fce11cc7e2677b4885678e5d5be"
WP6_CONTRACT_SEAL = "64f3ee8279085c35857845ee7c4a4c6d2660695e3c74f43695126c7e5329e123"
WP6_AUTHORITY_SEAL = "3062a5197fa1fcbe50f60b624b75b2be37c55a0c1193d1eeeffc03e7f03caaf0"
WP8H_CONTRACT_SEAL = "387ef6a1385363ec1ceb260851c0c606e1410d5962bc99d76cb99904cc75bd5f"
WP8H_AUTHORITY_SEAL = "9a128600ba9ce4f2d6d503a393d41c54d413b75717e5687f9118b0e169bac3f1"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
MAX_TEXT_BYTES = 1_000_000

METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-license-transition-authority", LT1_AUTHORITY_SEAL),
    ("parent-host-protocol-contract", WP6_CONTRACT_SEAL),
    ("parent-host-protocol-authority", WP6_AUTHORITY_SEAL),
    ("parent-candidate-role-contract", WP8H_CONTRACT_SEAL),
    ("parent-candidate-role-authority", WP8H_AUTHORITY_SEAL),
    ("protocol-status", "candidate-controlled-host-protocol-admitted"),
    ("host-status", "runtime-attestation-required"),
    ("role", "naux-register-residency-candidate"),
    ("baseline-role", "naux-residual"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("target", "x86_64-unknown-linux-gnu"),
    ("observation", "ephemeral-canonical-stdout-only"),
    ("host-policy", "reuse-exact-wp6-facts-refusals-and-fingerprint"),
)
GATES = (
    ("01", "license-transition", "required", "exact-current-apache-authority"),
    ("02", "candidate-role", "required", "exact-wp8h-isolated-role"),
    ("03", "host-protocol", "required", "exact-wp6-historical-authority"),
    ("04", "host-facts", "required", "exact-wp6-fact-schema"),
    ("05", "host-refusals", "required", "exact-wp6-refusal-schema"),
    ("06", "source-state", "required", "clean-exact-caller-commit"),
    ("07", "static-isolation", "required", "no-host-no-clock-no-execution"),
    ("08", "role-isolation", "required", "does-not-replace-wp5f"),
    ("09", "observation", "required", "ephemeral-only-no-retention"),
)
CLOSURES = (
    ("01", "candidate-controlled-host-protocol-unavailable", "closed", "wp8i-authority"),
)
BLOCKERS = (
    ("01", "eligible-candidate-host-attestation-unavailable"),
    ("02", "candidate-measurement-runner-unavailable"),
    ("03", "candidate-raw-measurement-evidence-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8I"),
    ("authority-id", "s4-register-residency-controlled-host-v1"),
    ("protocol-status", "candidate-controlled-host-protocol-admitted"),
    ("host-status", "runtime-attestation-required"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-host.yml",
    "distribution/s4-performance/WP8I-HOST.tsv",
    "distribution/s4-performance/WP8I-NONCLAIMS.md",
    "distribution/s4-performance/WP8I-README.md",
    "scripts/s4_register_residency_host.py",
    "scripts/tests/test_s4_register_residency_host.py",
    "scripts/tests/test_s4_register_residency_host_static.py",
)


class CandidateHostError(RuntimeError):
    """A fail-closed WP8I composition or observation error."""


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
    candidate: wp8h.Admission
    host_contract: wp6.Contract
    host_authority: wp6.Authority
    static_report: bytes
    static_root: str


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_regular(path: Path, label: str) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size > MAX_TEXT_BYTES:
        raise CandidateHostError(f"{label} is not a bounded regular file")
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
        raise CandidateHostError(f"{label} changed while read")
    return raw


def _canonical(raw: bytes, label: str) -> list[str]:
    if not raw or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise CandidateHostError(f"{label} has invalid canonical extent")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise CandidateHostError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise CandidateHostError(f"{label} contains blank or padded rows")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    raw = _read_regular(path, path.name)
    lines = _canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise CandidateHostError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]) or _sha256(domain + body) != fields[1]:
        raise CandidateHostError(f"{path.name} seal drifted")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL:
        raise CandidateHostError("WP8I contract identity drifted")
    expected = [f"meta\t{key}\t{value}" for key, value in METADATA]
    expected.extend(f"gate\t{ordinal}\t{name}\t{status}\t{detail}" for ordinal, name, status, detail in GATES)
    expected.extend(f"closure\t{ordinal}\t{name}\t{status}\t{detail}" for ordinal, name, status, detail in CLOSURES)
    expected.extend(f"blocker\t{ordinal}\t{name}" for ordinal, name in BLOCKERS)
    if rows != expected:
        raise CandidateHostError("WP8I contract rows drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    prefix = [f"meta\t{key}\t{value}" for key, value in AUTHORITY_METADATA]
    prefix.extend(
        (
            f"component\thost-contract\tdistribution/s4-performance/WP8I-HOST.tsv\t{contract_seal}",
            f"parent\tlicense-transition-authority\tdistribution/license-transition/LT1-AUTHORITY.tsv\t{LT1_AUTHORITY_SEAL}",
            f"parent\thost-protocol-authority\tdistribution/s4-performance/WP6-AUTHORITY.tsv\t{WP6_AUTHORITY_SEAL}",
            f"parent\tcandidate-role-authority\tdistribution/s4-performance/WP8H-AUTHORITY.tsv\t{WP8H_AUTHORITY_SEAL}",
        )
    )
    if rows[: len(prefix)] != prefix:
        raise CandidateHostError("WP8I authority metadata or parent binding drifted")
    records: list[FileRecord] = []
    for row in rows[len(prefix) :]:
        fields = row.split("\t")
        if (
            len(fields) != 6
            or fields[0] != "file"
            or not MODE_RE.fullmatch(fields[1])
            or not UINT_RE.fullmatch(fields[2])
            or not HASH_RE.fullmatch(fields[3])
            or fields[4] not in EXPECTED_FILES
            or fields[5] != "candidate-host"
        ):
            raise CandidateHostError("WP8I authority file row is malformed")
        records.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise CandidateHostError("WP8I authority inventory drifted")
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
            raise CandidateHostError(f"bound WP8I file drifted: {record.path}")


def _verify_historical_host_files(root: Path, authority: wp6.Authority) -> None:
    snapshot_paths = {relative for *_fields, relative in lt1.TRANSITIONS}
    snapshot = root / "distribution/license-transition/pre-apache"
    for record in authority.files:
        path = snapshot / record.path if record.path in snapshot_paths else root / record.path
        raw = _read_regular(path, f"WP6 historical {record.path}")
        if (
            stat.S_IFREG | stat.S_IMODE(path.lstat().st_mode) != record.mode
            or len(raw) != record.size
            or _sha256(raw) != record.sha256
        ):
            raise CandidateHostError(f"WP6 historical authority drifted: {record.path}")


def _verify_composition(
    root: Path,
) -> tuple[wp8h.Admission, wp6.Contract, wp6.Authority]:
    transition = lt1.validate(root)
    if transition.authority.seal != LT1_AUTHORITY_SEAL:
        raise CandidateHostError("Apache transition authority drifted")
    candidate = wp8h.validate(root)
    if (
        candidate.contract.seal != WP8H_CONTRACT_SEAL
        or candidate.authority.seal != WP8H_AUTHORITY_SEAL
    ):
        raise CandidateHostError("WP8H candidate role identity drifted")
    host_contract = wp6.parse_contract(root / "distribution/s4-performance/WP6-HOST.tsv")
    host_authority = wp6.parse_authority(
        root / "distribution/s4-performance/WP6-AUTHORITY.tsv", host_contract.seal
    )
    if host_contract.seal != WP6_CONTRACT_SEAL or host_authority.seal != WP6_AUTHORITY_SEAL:
        raise CandidateHostError("WP6 host protocol identity drifted")
    _verify_historical_host_files(root, host_authority)
    return candidate, host_contract, host_authority


def _verify_source_boundary(root: Path) -> None:
    workflow = _read_regular(
        root / ".github/workflows/s4-register-residency-host.yml", "WP8I workflow"
    ).decode()
    required = (
        "scripts/license_transition.py",
        "scripts/s4_register_residency_host.py",
        "test_s4_register_residency_host_static",
        "test_s4_register_residency_host",
    )
    if any(token not in workflow for token in required):
        raise CandidateHostError("WP8I workflow omits a required gate")
    source = _read_regular(root / "scripts/s4_register_residency_host.py", "WP8I validator").decode()
    forbidden = (
        "." + "monotonic(",
        "." + "perf_counter(",
        "." + "time_ns(",
        "." + "clock_gettime(",
        "duration" + "_ns",
        "runtime" + "_ns",
    )
    if any(token in source for token in forbidden):
        raise CandidateHostError("WP8I crossed its no-measurement boundary")
    expected = {
        "WP8I-AUTHORITY.tsv",
        "WP8I-HOST.tsv",
        "WP8I-NONCLAIMS.md",
        "WP8I-README.md",
    }
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP8I-*")
        if path.is_file()
    }
    if actual != expected:
        raise CandidateHostError("unexpected WP8I distribution artifact")


def _static_report(contract: Contract, authority: Authority) -> bytes:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"candidate-role-authority\t{WP8H_AUTHORITY_SEAL}",
        f"host-protocol-authority\t{WP6_AUTHORITY_SEAL}",
        "protocol-status\tcandidate-controlled-host-protocol-admitted",
        "host-status\tnot-observed",
        "role\tnaux-register-residency-candidate",
        "baseline-role\tnaux-residual",
        "claim-status\tnot-admitted",
        "timing-status\tforbidden",
        "mode\tstatic-authority",
        "gates\t9",
        "blockers\t3",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    return body + f"report-root\t{_sha256(REPORT_DOMAIN + body)}\n".encode()


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    candidate, host_contract, host_authority = _verify_composition(root)
    contract = parse_contract(root / "distribution/s4-performance/WP8I-HOST.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP8I-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_source_boundary(root)
    report = _static_report(contract, authority)
    report_root = report.decode().split("report-root\t", 1)[1].strip()
    return Admission(
        contract,
        authority,
        candidate,
        host_contract,
        host_authority,
        report,
        report_root,
    )


def _verify_observation(observation: wp6.HostObservation) -> None:
    expected_facts = tuple(name for _ordinal, name in wp6.CONTRACT_FACTS)
    if tuple(name for name, _value in observation.facts) != expected_facts:
        raise CandidateHostError("candidate host fact schema drifted")
    fact_body = b"".join(
        f"fact\t{name}\t{wp6._safe_fact(value, name)}\n".encode()
        for name, value in observation.facts
    )
    if _sha256(wp6.FINGERPRINT_DOMAIN + fact_body) != observation.fingerprint:
        raise CandidateHostError("candidate host fingerprint drifted")
    refusal_order = tuple(name for _ordinal, name in wp6.CONTRACT_REFUSALS)
    expected_refusals = tuple(name for name in refusal_order if name in observation.refusals)
    if observation.refusals != expected_refusals or len(set(observation.refusals)) != len(observation.refusals):
        raise CandidateHostError("candidate host refusal schema drifted")


def observe(root: Path, expected_commit: str | None) -> wp6.HostObservation:
    observation = wp6.observe(root.resolve(strict=True), expected_commit)
    _verify_observation(observation)
    return observation


def observation_report(admission: Admission, observation: wp6.HostObservation) -> bytes:
    _verify_observation(observation)
    rows = [
        REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"candidate-role-authority\t{WP8H_AUTHORITY_SEAL}",
        f"host-protocol-authority\t{WP6_AUTHORITY_SEAL}",
        "protocol-status\tcandidate-controlled-host-protocol-admitted",
        f"host-status\t{'eligible-ephemeral-observation' if observation.eligible else 'ineligible-observation'}",
        "role\tnaux-register-residency-candidate",
        "baseline-role\tnaux-residual",
        "claim-status\tnot-admitted",
        "timing-status\tforbidden",
        "mode\thost-observation",
        f"fingerprint\t{observation.fingerprint}",
    ]
    rows.extend(f"fact\t{key}\t{value}" for key, value in observation.facts)
    rows.append(f"refusals\t{len(observation.refusals)}")
    refusal_ordinals = {name: ordinal for ordinal, name in wp6.CONTRACT_REFUSALS}
    rows.extend(f"refusal\t{refusal_ordinals[name]}\t{name}" for name in observation.refusals)
    body = b"".join(f"{row}\n".encode() for row in rows)
    return body + f"report-root\t{_sha256(REPORT_DOMAIN + body)}\n".encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--observe", action="store_true")
    parser.add_argument("--expected-commit")
    parser.add_argument("--require-eligible", action="store_true")
    arguments = parser.parse_args()
    if arguments.require_eligible and not arguments.observe:
        parser.error("--require-eligible requires --observe")
    try:
        admission = validate(arguments.root)
        if not arguments.observe:
            sys.stdout.buffer.write(admission.static_report)
            return 0
        observation = observe(arguments.root, arguments.expected_commit)
        sys.stdout.buffer.write(observation_report(admission, observation))
        return 0 if observation.eligible or not arguments.require_eligible else 2
    except (
        CandidateHostError,
        lt1.TransitionError,
        wp8h.CandidateRoleError,
        wp8h.wp8g.ProcessReplayError,
        wp6.HostControlError,
        OSError,
        subprocess.SubprocessError,
        ValueError,
    ) as error:
        print(f"S4-WP8I validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
