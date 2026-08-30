#!/usr/bin/env python3
"""Validate or explicitly run the S4-WP8M same-session paired runner."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import s4_measurement_runner as wp7c
import s4_register_residency_measurement_runner as wp8k


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PAIRED-RUNNER-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PAIRED-RUNNER-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PAIRED-RUNNER-REPORT\t1"
SESSION_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PAIRED-RAW-SESSION\t1"
BUNDLE_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PAIRED-RAW-BUNDLE\t1"
TOOLCHAIN_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PAIRED-TOOLCHAINS\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-paired-runner:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-paired-runner:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-paired-runner:report:v1\0"
SESSION_DOMAIN = b"NAUX:s4-register-residency-paired-raw-session:v1\0"
BUNDLE_DOMAIN = b"NAUX:s4-register-residency-paired-raw-bundle:v1\0"
TOOLCHAIN_DOMAIN = b"NAUX:s4-register-residency-paired-toolchains:v1\0"
CONTRACT_SEAL = "218794532dae9820babfda71859b3227b0d4f64ec277c876e13f28b2adca553a"
WP8K_AUTHORITY_SEAL = "3c7f1ce549764dd5a2d3bc28dfeec3c091aaae835f44490ac6a3418e0f852fc2"
WP8I_AUTHORITY_SEAL = wp8k.WP8I_AUTHORITY_SEAL
WP8J_AUTHORITY_SEAL = wp8k.WP8J_AUTHORITY_SEAL
WP7B_AUTHORITY_SEAL = wp7c.WP7B_NAUX_AUTHORITY_SEAL
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
MAX_TEXT_BYTES = 4_000_000
BASELINE_ROLE = "01"
CANDIDATE_ROLE = wp8k.ROLE_ORDINAL
ROLES = (
    (BASELINE_ROLE, "naux-residual", "native-clean", 1),
    (CANDIDATE_ROLE, wp8k.ROLE_NAME, "candidate-isolated", wp8k.ROLE_OWNER),
)
KERNELS = wp8k.KERNELS
WARMUP_MINIMUM_NS = wp8k.WARMUP_MINIMUM_NS
SAMPLE_PAIR_COUNT = wp8k.SAMPLE_COUNT
MAX_WARMUP_PAIRS = wp8k.MAX_WARMUP_INVOCATIONS

METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-candidate-runner-authority", WP8K_AUTHORITY_SEAL),
    ("parent-candidate-host-authority", WP8I_AUTHORITY_SEAL),
    ("parent-candidate-carrier-authority", WP8J_AUTHORITY_SEAL),
    ("parent-baseline-carrier-authority", WP7B_AUTHORITY_SEAL),
    ("runner-status", "same-session-paired-runner-structurally-admitted"),
    ("acquisition-status", "retained-eligible-wp8i-host-required"),
    ("claim-status", "not-admitted"),
    ("default-mode", "static-no-host-no-clock-no-build-no-execution"),
    ("acquire-mode", "explicit-only"),
    ("build-policy", "same-session-same-resolved-cargo-rustc"),
    ("warmup-policy", "paired-abba-retain-until-both-cumulative-100000000ns"),
    ("sample-policy", "kernel-major-exact30-pairs-odd-ab-even-ba"),
    ("sample-invocations", "240"),
    ("result-policy", "fixed-le56-exact-role-owner-and-parity"),
    ("publication-policy", "atomic-new-output-or-no-bundle"),
    ("target", "x86_64-unknown-linux-gnu"),
)
GATES = (
    ("01", "static-isolation", "required", "no-host-no-clock-no-build-no-execution"),
    ("02", "retained-attestation", "required", "exact-eligible-wp8i-report"),
    ("03", "live-reattestation", "required", "before-build-after-build-after-samples"),
    ("04", "checkout", "required", "clean-exact-attested-commit"),
    ("05", "toolchains", "required", "same-resolved-cargo-rustc-identities"),
    ("06", "artifacts", "required", "four-baseline-and-four-candidate-artifacts"),
    ("07", "warmup", "required", "paired-all-retained-both-cumulative-minimum"),
    ("08", "schedule", "required", "odd-ab-even-ba-no-drop-no-retry"),
    ("09", "samples", "required", "exact120-pairs-and240-invocations"),
    ("10", "parity", "required", "exact-oracle-and-role-owner-every-invocation"),
    ("11", "atomic-publication", "required", "complete-paired-raw-bundle-only"),
)
CLOSURES = (
    ("01", "cross-session-comparison-bias", "closed", "same-session-abba-pairing"),
)
BLOCKERS = (
    ("01", "eligible-candidate-host-attestation-unavailable"),
    ("02", "paired-raw-measurement-evidence-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8M"),
    ("authority-id", "s4-register-residency-paired-runner-v1"),
    ("runner-status", "same-session-paired-runner-structurally-admitted"),
    ("acquisition-status", "retained-eligible-wp8i-host-required"),
    ("claim-status", "not-admitted"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-paired-runner.yml",
    "distribution/s4-performance/WP8M-PAIRED-RUNNER.tsv",
    "distribution/s4-performance/WP8M-NONCLAIMS.md",
    "distribution/s4-performance/WP8M-README.md",
    "scripts/s4_register_residency_paired_runner.py",
    "scripts/tests/test_s4_register_residency_paired_runner.py",
    "scripts/tests/test_s4_register_residency_paired_runner_static.py",
)


class PairedRunnerError(RuntimeError):
    """A fail-closed WP8M validation or acquisition error."""


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
    candidate: wp8k.Admission
    static_report: bytes
    report_root: str


@dataclass(frozen=True)
class PairRecord:
    kernel: str
    ordinal: int
    order: str
    first: wp7c.Invocation
    second: wp7c.Invocation


@dataclass(frozen=True)
class PairedAcquisition:
    builds: tuple[wp7c.RoleBuild, wp7c.RoleBuild]
    warmups: tuple[PairRecord, ...]
    samples: tuple[PairRecord, ...]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_regular(path: Path, label: str, maximum: int = MAX_TEXT_BYTES) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise PairedRunnerError(f"{label} is not a bounded regular file")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        raw = handle.read(maximum + 1)
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
        raise PairedRunnerError(f"{label} changed while read")
    return raw


def _canonical(raw: bytes, label: str) -> list[str]:
    if not raw or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise PairedRunnerError(f"{label} has invalid canonical extent")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise PairedRunnerError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise PairedRunnerError(f"{label} contains blank or padded rows")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    raw = _read_regular(path, path.name)
    lines = _canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise PairedRunnerError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]) or _sha256(domain + body) != fields[1]:
        raise PairedRunnerError(f"{path.name} seal drifted")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL:
        raise PairedRunnerError("WP8M contract identity drifted")
    expected = [f"meta\t{key}\t{value}" for key, value in METADATA]
    expected.extend(
        f"role\t{ordinal}\t{name}\t{status}\t{owner}"
        for ordinal, name, status, owner in ROLES
    )
    expected.extend(
        f"kernel\t{ordinal}\t{name}\t{oracle}" for ordinal, name, oracle in KERNELS
    )
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
        raise PairedRunnerError("WP8M contract rows drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    prefix = [f"meta\t{key}\t{value}" for key, value in AUTHORITY_METADATA]
    prefix.extend((
        f"component\tpaired-runner-contract\tdistribution/s4-performance/WP8M-PAIRED-RUNNER.tsv\t{contract_seal}",
        f"parent\tcandidate-runner-authority\tdistribution/s4-performance/WP8K-AUTHORITY.tsv\t{WP8K_AUTHORITY_SEAL}",
        f"parent\tcandidate-host-authority\tdistribution/s4-performance/WP8I-AUTHORITY.tsv\t{WP8I_AUTHORITY_SEAL}",
        f"parent\tcandidate-carrier-authority\tdistribution/s4-performance/WP8J-AUTHORITY.tsv\t{WP8J_AUTHORITY_SEAL}",
        f"parent\tbaseline-carrier-authority\tdistribution/s4-performance/WP7B-AUTHORITY.tsv\t{WP7B_AUTHORITY_SEAL}",
    ))
    if rows[: len(prefix)] != prefix:
        raise PairedRunnerError("WP8M authority metadata or parent binding drifted")
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
            or fields[5] != "same-session-paired-runner"
        ):
            raise PairedRunnerError("WP8M authority file row is malformed")
        records.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise PairedRunnerError("WP8M authority inventory drifted")
    return Authority(tuple(records), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        raw = _read_regular(path, record.path)
        mode = stat.S_IFREG | stat.S_IMODE(path.lstat().st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise PairedRunnerError(f"bound WP8M file drifted: {record.path}")


def _static_report(contract: Contract, authority: Authority) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"candidate-runner-authority\t{WP8K_AUTHORITY_SEAL}",
        "runner-status\tsame-session-paired-runner-structurally-admitted",
        "acquisition-status\tretained-eligible-wp8i-host-required",
        "mode\tstatic-no-host-no-clock-no-build-no-execution",
        "sample-pairs-required\t120",
        "sample-invocations-required\t240",
        "claim-status\tnot-admitted",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    candidate = wp8k.validate(root)
    if (
        candidate.authority.seal != WP8K_AUTHORITY_SEAL
        or candidate.host.authority.seal != WP8I_AUTHORITY_SEAL
        or candidate.carrier.authority.seal != WP8J_AUTHORITY_SEAL
        or candidate.carrier.wrapper.authority.seal != WP7B_AUTHORITY_SEAL
    ):
        raise PairedRunnerError("WP8M parent authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP8M-PAIRED-RUNNER.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP8M-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    report, report_root = _static_report(contract, authority)
    return Admission(contract, authority, candidate, report, report_root)


def build_pair(
    root: Path,
    directory: Path,
    admission: Admission,
    *,
    cargo_command: str,
    rustc_command: str,
) -> tuple[wp7c.RoleBuild, wp7c.RoleBuild]:
    cargo = wp7c._resolve_tool(cargo_command, "Cargo")
    rustc = wp7c._resolve_tool(rustc_command, "rustc")
    baseline_dir = directory / "baseline"
    candidate_dir = directory / "candidate"
    baseline_dir.mkdir()
    candidate_dir.mkdir()
    baseline = wp7c._build_naux_role(
        root, baseline_dir, admission.candidate.carrier.wrapper, cargo, rustc
    )
    candidate = wp8k.build_candidate(
        root,
        candidate_dir,
        admission.candidate.carrier,
        cargo_command=os.fspath(cargo),
        rustc_command=os.fspath(rustc),
    )
    verify_build_pair((baseline, candidate))
    return baseline, candidate


def _verify_baseline(build: wp7c.RoleBuild) -> None:
    if (
        (build.ordinal, build.name, build.path_status)
        != (BASELINE_ROLE, "naux-residual", "native-clean")
        or build.compile_ns <= 0
        or build.specialize_ns <= 0
        or tuple(artifact.role for artifact in build.artifacts) != (BASELINE_ROLE,) * 4
        or tuple(artifact.kernel for artifact in build.artifacts)
        != tuple(ordinal for ordinal, _name, _oracle in KERNELS)
        or tuple(tool.name for tool in build.toolchains) != ("cargo", "rustc")
    ):
        raise PairedRunnerError("baseline build role or extent drifted")
    artifacts = tuple(
        wp7c._artifact(artifact.role, artifact.kernel, artifact.path)
        for artifact in build.artifacts
    )
    toolchains = tuple(
        wp7c._tool_identity(tool.name, Path(tool.executable_path))
        for tool in build.toolchains
    )
    if (
        artifacts != build.artifacts
        or toolchains != build.toolchains
        or wp7c.aggregate_binary_identity(artifacts) != build.binary_hash
        or wp7c.aggregate_toolchain_identity(toolchains) != build.toolchain_hash
    ):
        raise PairedRunnerError("baseline artifact or toolchain identity drifted")


def verify_build_pair(
    builds: tuple[wp7c.RoleBuild, wp7c.RoleBuild],
) -> None:
    if len(builds) != 2:
        raise PairedRunnerError("paired build extent drifted")
    baseline, candidate = builds
    _verify_baseline(baseline)
    wp8k.verify_build_identity(candidate)
    if (
        candidate.compile_ns <= 0
        or candidate.specialize_ns <= 0
        or tuple(tool.name for tool in candidate.toolchains) != ("cargo", "rustc")
        or baseline.toolchains != candidate.toolchains
        or baseline.toolchain_hash != candidate.toolchain_hash
    ):
        raise PairedRunnerError("paired builds do not share one exact toolchain identity")


def _execute(artifact: wp7c.Artifact) -> tuple[wp7c.CarrierResult, int, int]:
    if artifact.role == BASELINE_ROLE:
        return wp7c.execute_carrier(artifact)
    if artifact.role == CANDIDATE_ROLE:
        return wp8k.execute_candidate(artifact)
    raise PairedRunnerError("paired schedule contains an unknown role")


def _invocation(
    build: wp7c.RoleBuild,
    artifact: wp7c.Artifact,
    ordinal: int,
) -> wp7c.Invocation:
    result, envelope, rss = _execute(artifact)
    oracle = next(value for kernel, _name, value in KERNELS if kernel == artifact.kernel)
    owner = next(value for role, _name, _status, value in ROLES if role == build.ordinal)
    if (
        result.checksum != oracle
        or result.owner != owner
        or result.duration_ns <= 0
        or envelope <= result.duration_ns
        or rss <= 0
    ):
        raise PairedRunnerError("paired invocation parity, owner, envelope, or RSS drifted")
    return wp7c.Invocation(
        build.ordinal,
        artifact.kernel,
        ordinal,
        result.duration_ns,
        result.checksum,
        build.path_status,
        envelope,
        rss,
    )


def _pair(
    builds: tuple[wp7c.RoleBuild, wp7c.RoleBuild], kernel: str, ordinal: int
) -> PairRecord:
    try:
        artifacts = {
            build.ordinal: next(item for item in build.artifacts if item.kernel == kernel)
            for build in builds
        }
    except StopIteration as error:
        raise PairedRunnerError("paired build is missing a scheduled kernel artifact") from error
    order = "AB" if ordinal % 2 else "BA"
    role_order = (BASELINE_ROLE, CANDIDATE_ROLE) if order == "AB" else (CANDIDATE_ROLE, BASELINE_ROLE)
    build_map = {build.ordinal: build for build in builds}
    first = _invocation(build_map[role_order[0]], artifacts[role_order[0]], ordinal)
    second = _invocation(build_map[role_order[1]], artifacts[role_order[1]], ordinal)
    return PairRecord(kernel, ordinal, order, first, second)


def collect_paired_invocations(
    builds: tuple[wp7c.RoleBuild, wp7c.RoleBuild],
) -> PairedAcquisition:
    warmups = []
    samples = []
    for kernel, _name, _oracle in KERNELS:
        totals = {BASELINE_ROLE: 0, CANDIDATE_ROLE: 0}
        ordinal = 0
        while min(totals.values()) < WARMUP_MINIMUM_NS:
            ordinal += 1
            if ordinal > MAX_WARMUP_PAIRS:
                raise PairedRunnerError("paired warmup ceiling reached")
            pair = _pair(builds, kernel, ordinal)
            warmups.append(pair)
            totals[pair.first.role] += pair.first.duration_ns
            totals[pair.second.role] += pair.second.duration_ns
        for sample_ordinal in range(1, SAMPLE_PAIR_COUNT + 1):
            samples.append(_pair(builds, kernel, sample_ordinal))
    data = PairedAcquisition(builds, tuple(warmups), tuple(samples))
    _validate_acquisition(data)
    return data


def _validate_pair(pair: PairRecord, expected_kernel: str, expected_ordinal: int) -> None:
    expected_order = "AB" if expected_ordinal % 2 else "BA"
    expected_roles = (
        (BASELINE_ROLE, CANDIDATE_ROLE)
        if expected_order == "AB"
        else (CANDIDATE_ROLE, BASELINE_ROLE)
    )
    oracle = next(value for kernel, _name, value in KERNELS if kernel == expected_kernel)
    statuses = {role: status for role, _name, status, _owner in ROLES}
    if (
        (pair.kernel, pair.ordinal, pair.order)
        != (expected_kernel, expected_ordinal, expected_order)
        or (pair.first.role, pair.second.role) != expected_roles
    ):
        raise PairedRunnerError("paired AB/BA schedule drifted")
    for invocation in (pair.first, pair.second):
        if (
            invocation.role not in statuses
            or invocation.kernel != expected_kernel
            or invocation.ordinal != expected_ordinal
            or invocation.checksum != oracle
            or invocation.path_status != statuses.get(invocation.role)
            or invocation.duration_ns <= 0
            or invocation.overhead_ns <= 0
            or invocation.rss_bytes <= 0
        ):
            raise PairedRunnerError("paired invocation content drifted")


def _validate_acquisition(data: PairedAcquisition) -> None:
    if tuple(build.ordinal for build in data.builds) != (BASELINE_ROLE, CANDIDATE_ROLE):
        raise PairedRunnerError("paired build order drifted")
    warmup_cursor = 0
    for kernel, _name, _oracle in KERNELS:
        totals = {BASELINE_ROLE: 0, CANDIDATE_ROLE: 0}
        totals_before_last = totals.copy()
        expected_ordinal = 1
        while warmup_cursor < len(data.warmups) and data.warmups[warmup_cursor].kernel == kernel:
            pair = data.warmups[warmup_cursor]
            _validate_pair(pair, kernel, expected_ordinal)
            totals_before_last = totals.copy()
            for invocation in (pair.first, pair.second):
                totals[invocation.role] += invocation.duration_ns
            expected_ordinal += 1
            warmup_cursor += 1
        if expected_ordinal == 1 or expected_ordinal - 1 > MAX_WARMUP_PAIRS:
            raise PairedRunnerError("paired warmup extent drifted")
        if min(totals.values()) < WARMUP_MINIMUM_NS:
            raise PairedRunnerError("paired warmup cumulative minimum was not met")
        if min(totals_before_last.values()) >= WARMUP_MINIMUM_NS:
            raise PairedRunnerError("paired warmup continued after both roles met the minimum")
    if warmup_cursor != len(data.warmups):
        raise PairedRunnerError("paired warmup has unknown or trailing rows")
    cursor = 0
    for kernel, _name, _oracle in KERNELS:
        for ordinal in range(1, SAMPLE_PAIR_COUNT + 1):
            if cursor >= len(data.samples):
                raise PairedRunnerError("paired sample set is truncated")
            _validate_pair(data.samples[cursor], kernel, ordinal)
            cursor += 1
    if cursor != len(data.samples) or cursor != len(KERNELS) * SAMPLE_PAIR_COUNT:
        raise PairedRunnerError("paired sample extent or ordering drifted")


def build_raw_session(
    runner: Admission,
    retained: wp8k.RetainedHost,
    data: PairedAcquisition,
) -> tuple[bytes, str]:
    _validate_acquisition(data)
    rows = [
        SESSION_MAGIC,
        f"meta\trunner-authority\t{runner.authority.seal}",
        f"meta\thost-attestation\t{retained.report_root}",
        f"meta\tsource-commit\t{retained.commit}",
        f"meta\tbaseline-carrier-authority\t{WP7B_AUTHORITY_SEAL}",
        f"meta\tcandidate-carrier-authority\t{WP8J_AUTHORITY_SEAL}",
        "meta\tschedule\tkernel-major-odd-ab-even-ba",
        "meta\tclaim-status\tnot-admitted",
    ]
    for build in data.builds:
        rows.append(
            f"build\t{build.ordinal}\t{build.name}\t{build.binary_hash}\t"
            f"{build.toolchain_hash}\t{build.compile_ns}\t{build.specialize_ns}\t{build.code_size}"
        )
    rows.append(f"warmup-pairs\t{len(data.warmups)}")
    for pair in data.warmups:
        rows.append(f"warmup-pair\t{pair.kernel}\t{pair.ordinal:06}\t{pair.order}")
        for position, item in enumerate((pair.first, pair.second), 1):
            rows.append(
                f"warmup-run\t{pair.kernel}\t{pair.ordinal:06}\t{position}\t{item.role}\t"
                f"{item.duration_ns}\t{item.checksum}\t{item.envelope_ns}\t{item.rss_bytes}\t{item.path_status}"
            )
    rows.append(f"sample-pairs\t{len(data.samples)}")
    for pair in data.samples:
        rows.append(f"sample-pair\t{pair.kernel}\t{pair.ordinal:02}\t{pair.order}")
        for position, item in enumerate((pair.first, pair.second), 1):
            rows.append(
                f"sample-run\t{pair.kernel}\t{pair.ordinal:02}\t{position}\t{item.role}\t"
                f"{item.duration_ns}\t{item.checksum}\t{item.envelope_ns}\t{item.rss_bytes}\t{item.path_status}"
            )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(SESSION_DOMAIN + body)
    return body + f"session-root\t{root}\n".encode(), root


def publish_bundle(
    root: Path,
    output: Path,
    runner: Admission,
    retained: wp8k.RetainedHost,
    data: PairedAcquisition,
    session: bytes,
    session_root: str,
    host_attestation_path: Path,
) -> str:
    verify_build_pair(data.builds)
    _validate_acquisition(data)
    output = wp7c._checked_output(root, output)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.stage-", dir=output.parent))
    published = False
    try:
        tool_rows = [
            TOOLCHAIN_MAGIC,
            f"meta\trunner-authority\t{runner.authority.seal}",
            f"meta\tsource-commit\t{retained.commit}",
            "meta\tclaim-status\tnot-admitted",
        ]
        for build in data.builds:
            for ordinal, tool in enumerate(build.toolchains, 1):
                tool_rows.append(
                    f"tool\t{build.ordinal}\t{ordinal:02}\t{tool.name}\t{tool.executable_path}\t"
                    f"{tool.executable_hash}\t{tool.version_hash}\t{tool.version_hex}"
                )
        tool_body = b"".join(f"{row}\n".encode() for row in tool_rows)
        tool_receipt = tool_body + (
            f"toolchain-root\t{_sha256(TOOLCHAIN_DOMAIN + tool_body)}\n"
        ).encode()
        reproduction = (
            "NAUX-S4-REGISTER-RESIDENCY-PAIRED-REPRODUCTION\t1\n"
            f"source-commit\t{retained.commit}\n"
            f"runner-authority\t{runner.authority.seal}\n"
            f"host-attestation-root\t{retained.report_root}\n"
            f"original-host-attestation\t{host_attestation_path.resolve(strict=True)}\n"
            "policy\tnew-eligible-attestation-and-new-output-required-for-each-run\n"
        ).encode()
        files: list[tuple[str, bytes, int]] = [
            ("HOST-ATTESTATION.tsv", retained.raw, 0o600),
            ("RAW-PAIRED-SESSION.tsv", session, 0o600),
            ("TOOLCHAINS.tsv", tool_receipt, 0o600),
            ("REPRODUCE.tsv", reproduction, 0o600),
        ]
        kernel_names = {ordinal: name for ordinal, name, _oracle in KERNELS}
        role_directories = {BASELINE_ROLE: "baseline", CANDIDATE_ROLE: "candidate"}
        for build in data.builds:
            for artifact in build.artifacts:
                raw = wp7c._regular_bytes(
                    artifact.path, f"{build.name}/{artifact.kernel} publication artifact"
                )
                if len(raw) != artifact.size or _sha256(raw) != artifact.sha256:
                    raise PairedRunnerError("artifact drifted while preparing paired publication")
                files.append((
                    f"artifacts/{role_directories[build.ordinal]}/{artifact.kernel}-{kernel_names[artifact.kernel]}",
                    raw,
                    0o700,
                ))
        manifest = []
        for relative, raw, mode in files:
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            wp7c._write_regular(destination, raw, mode)
            manifest.append((relative, len(raw), _sha256(raw)))
        rows = [
            BUNDLE_MAGIC,
            f"meta\trunner-authority\t{runner.authority.seal}",
            f"meta\thost-attestation\t{retained.report_root}",
            f"meta\tsession-root\t{session_root}",
            f"meta\tsource-commit\t{retained.commit}",
            "meta\tschedule\tkernel-major-odd-ab-even-ba",
            "meta\tclaim-status\tnot-admitted",
            f"meta\tfile-count\t{len(manifest)}",
        ]
        rows.extend(f"file\t{relative}\t{size}\t{digest}" for relative, size, digest in manifest)
        body = b"".join(f"{row}\n".encode() for row in rows)
        bundle_root = _sha256(BUNDLE_DOMAIN + body)
        wp7c._write_regular(stage / "MANIFEST.tsv", body + f"bundle-root\t{bundle_root}\n".encode())
        directory = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        wp7c._rename_noreplace(stage, output)
        published = True
        parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        return bundle_root
    finally:
        if not published:
            shutil.rmtree(stage, ignore_errors=True)


def acquire(
    root: Path,
    host_attestation: Path,
    output: Path,
    *,
    cargo_command: str,
    rustc_command: str,
) -> tuple[bytes, str]:
    root = root.resolve(strict=True)
    runner = validate(root)
    retained = wp8k.parse_retained_host(host_attestation, runner.candidate)
    checked_output = wp7c._checked_output(root, output)
    wp8k.verify_live_host(root, retained)
    with tempfile.TemporaryDirectory(prefix="naux-s4-wp8m-build-") as directory_name:
        builds = build_pair(
            root,
            Path(directory_name),
            runner,
            cargo_command=cargo_command,
            rustc_command=rustc_command,
        )
        wp8k.verify_live_host(root, retained)
        data = collect_paired_invocations(builds)
        verify_build_pair(builds)
        wp8k.verify_live_host(root, retained)
        session, session_root = build_raw_session(runner, retained, data)
        bundle_root = publish_bundle(
            root,
            checked_output,
            runner,
            retained,
            data,
            session,
            session_root,
            host_attestation,
        )
    rows = (
        REPORT_MAGIC,
        f"contract\t{runner.contract.seal}",
        f"authority\t{runner.authority.seal}",
        f"host-attestation\t{retained.report_root}",
        f"session-root\t{session_root}",
        f"bundle-root\t{bundle_root}",
        "mode\texplicit-controlled-same-session-paired-acquisition",
        "sample-pairs\t120",
        "sample-invocations\t240",
        "claim-status\tnot-admitted",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    return body + f"report-root\t{_sha256(REPORT_DOMAIN + body)}\n".encode(), bundle_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--acquire", action="store_true")
    parser.add_argument("--host-attestation", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--rustc", default="rustc")
    arguments = parser.parse_args(argv)
    if arguments.acquire and (arguments.host_attestation is None or arguments.output is None):
        parser.error("--acquire requires --host-attestation and --output")
    if not arguments.acquire and (arguments.host_attestation is not None or arguments.output is not None):
        parser.error("host/output arguments require --acquire")
    if not arguments.acquire and (arguments.cargo != "cargo" or arguments.rustc != "rustc"):
        parser.error("toolchain arguments require --acquire")
    try:
        if arguments.acquire:
            report, _bundle = acquire(
                arguments.root,
                arguments.host_attestation,
                arguments.output,
                cargo_command=arguments.cargo,
                rustc_command=arguments.rustc,
            )
            sys.stdout.buffer.write(report)
        else:
            sys.stdout.buffer.write(validate(arguments.root).static_report)
        return 0
    except (
        PairedRunnerError,
        wp8k.CandidateRunnerError,
        wp7c.RunnerError,
        OSError,
        subprocess.SubprocessError,
        ValueError,
    ) as error:
        print(f"S4-WP8M validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
