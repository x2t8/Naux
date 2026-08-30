#!/usr/bin/env python3
"""Validate or explicitly run the S4-WP8K candidate acquisition runner."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import license_transition as lt1
import s4_measurement_runner as wp7c
import s4_register_residency_host as wp8i
import s4_register_residency_timing as wp8j


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-MEASUREMENT-RUNNER-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-MEASUREMENT-RUNNER-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-MEASUREMENT-RUNNER-REPORT\t1"
SESSION_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-RAW-SESSION\t1"
BUNDLE_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-RAW-BUNDLE\t1"
TOOLCHAIN_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-TOOLCHAINS\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-measurement-runner:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-measurement-runner:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-measurement-runner:report:v1\0"
SESSION_DOMAIN = b"NAUX:s4-register-residency-raw-session:v1\0"
BUNDLE_DOMAIN = b"NAUX:s4-register-residency-raw-bundle:v1\0"
TOOLCHAIN_DOMAIN = b"NAUX:s4-register-residency-toolchains:v1\0"
CONTRACT_SEAL = "fe93623ad43a452ea7d1f8915d8a4ea152a366a396177cf693e18a253d5cc3f9"
WP8I_CONTRACT_SEAL = "1da0e075623f18bed18f2ef3df464a152d1facf45c0a16f5e98d23c216d3f441"
WP8I_AUTHORITY_SEAL = "5f9e36d9f9994a5449fd6492b083b934799723fdc9b89e79d0003bc594beebb7"
WP8J_AUTHORITY_SEAL = "aaa90c3a2674f7c13208bbb895b8365c01bd5cc9b60c86ff26fa29727d9c11f1"
WP7C_AUTHORITY_SEAL = "b9dbfa5708eceac818f3b33904551ee7a86bc47f687b5d268e7470efc8d7a130"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
MAX_TEXT_BYTES = 4_000_000
ROLE_ORDINAL = "04"
ROLE_NAME = "naux-register-residency-candidate"
ROLE_OWNER = 4
N = 16_384
REPS = 50
WARMUP_MINIMUM_NS = 100_000_000
SAMPLE_COUNT = 30
MAX_WARMUP_INVOCATIONS = 100_000
PROCESS_TIMEOUT_SECONDS = 30
RESULT_MAGIC = b"NAUX7B01"
RESULT_BYTES = 56

METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-candidate-host-authority", WP8I_AUTHORITY_SEAL),
    ("parent-candidate-carrier-authority", WP8J_AUTHORITY_SEAL),
    ("parent-runner-engine-authority", WP7C_AUTHORITY_SEAL),
    ("runner-status", "candidate-measurement-runner-structurally-admitted"),
    ("acquisition-status", "retained-eligible-wp8i-host-required"),
    ("claim-status", "not-admitted"),
    ("default-mode", "static-no-host-no-clock-no-build-no-execution"),
    ("acquire-mode", "explicit-only"),
    ("role", ROLE_NAME),
    ("role-owner", str(ROLE_OWNER)),
    ("artifact-policy", "four-exact-wp8j-role-kernel-artifacts"),
    ("build-policy", "fixed-argv-no-shell"),
    ("warmup-policy", "retain-every-invocation-until-cumulative-100000000ns"),
    ("sample-policy", "kernel-major-exact30-no-drop-no-retry"),
    ("result-policy", "fixed-le56-owner-four-exact-parity"),
    ("publication-policy", "atomic-new-output-or-no-bundle"),
    ("target", "x86_64-unknown-linux-gnu"),
)
KERNELS = (
    ("01", "sum-dense", 6_710_476_800),
    ("02", "branch-mix", -69_189_632),
    ("03", "dot-product", 73_294_064_435_200),
    ("04", "list-update", 6_730_547_200),
)
GATES = (
    ("01", "static-isolation", "required", "no-host-no-clock-no-build-no-execution"),
    ("02", "retained-attestation", "required", "exact-eligible-wp8i-report"),
    ("03", "live-reattestation", "required", "exact-facts-fingerprint-commit"),
    ("04", "checkout", "required", "clean-exact-attested-commit"),
    ("05", "toolchains", "required", "stable-cargo-rustc-identities"),
    ("06", "artifacts", "required", "exact-wp8j-replay-and-aggregate-identity"),
    ("07", "warmup", "required", "all-invocations-retained-cumulative-minimum"),
    ("08", "samples", "required", "exact120-no-retry"),
    ("09", "parity", "required", "every-record-exact-owner-four"),
    ("10", "atomic-publication", "required", "complete-raw-bundle-only"),
)
CLOSURES = (("01", "candidate-measurement-runner-unavailable", "closed", "wp8k-explicit-runner"),)
BLOCKERS = (
    ("01", "eligible-candidate-host-attestation-unavailable"),
    ("02", "candidate-raw-measurement-evidence-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8K"),
    ("authority-id", "s4-register-residency-measurement-runner-v1"),
    ("runner-status", "candidate-measurement-runner-structurally-admitted"),
    ("acquisition-status", "retained-eligible-wp8i-host-required"),
    ("claim-status", "not-admitted"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-measurement-runner.yml",
    "distribution/s4-performance/WP8K-RUNNER.tsv",
    "distribution/s4-performance/WP8K-NONCLAIMS.md",
    "distribution/s4-performance/WP8K-README.md",
    "scripts/s4_register_residency_measurement_runner.py",
    "scripts/tests/test_s4_register_residency_measurement_runner.py",
    "scripts/tests/test_s4_register_residency_measurement_runner_static.py",
)


class CandidateRunnerError(RuntimeError):
    """A fail-closed WP8K validation or acquisition error."""


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
    host: wp8i.Admission
    carrier: wp8j.Admission
    static_report: bytes
    report_root: str


@dataclass(frozen=True)
class RetainedHost:
    raw: bytes
    report_root: str
    fingerprint: str
    facts: tuple[tuple[str, str], ...]

    @property
    def commit(self) -> str:
        return dict(self.facts)["git-commit"]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_regular(path: Path, label: str, maximum: int = MAX_TEXT_BYTES) -> bytes:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise CandidateRunnerError(f"{label} is not a bounded regular file")
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
        raise CandidateRunnerError(f"{label} changed while read")
    return raw


def _canonical(raw: bytes, label: str, maximum: int = MAX_TEXT_BYTES) -> list[str]:
    if not raw or len(raw) > maximum or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise CandidateRunnerError(f"{label} has invalid canonical extent")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise CandidateRunnerError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise CandidateRunnerError(f"{label} contains blank or padded rows")
    return lines


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    raw = _read_regular(path, path.name)
    lines = _canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise CandidateRunnerError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]) or _sha256(domain + body) != fields[1]:
        raise CandidateRunnerError(f"{path.name} seal drifted")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL:
        raise CandidateRunnerError("WP8K contract identity drifted")
    expected = [f"meta\t{key}\t{value}" for key, value in METADATA]
    expected.extend(f"kernel\t{ordinal}\t{name}\t{oracle}" for ordinal, name, oracle in KERNELS)
    expected.extend(f"gate\t{ordinal}\t{name}\t{status}\t{detail}" for ordinal, name, status, detail in GATES)
    expected.extend(f"closure\t{ordinal}\t{name}\t{status}\t{detail}" for ordinal, name, status, detail in CLOSURES)
    expected.extend(f"blocker\t{ordinal}\t{name}" for ordinal, name in BLOCKERS)
    if rows != expected:
        raise CandidateRunnerError("WP8K contract rows drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    prefix = [f"meta\t{key}\t{value}" for key, value in AUTHORITY_METADATA]
    prefix.extend((
        f"component\tcandidate-runner-contract\tdistribution/s4-performance/WP8K-RUNNER.tsv\t{contract_seal}",
        f"parent\tcandidate-host-authority\tdistribution/s4-performance/WP8I-AUTHORITY.tsv\t{WP8I_AUTHORITY_SEAL}",
        f"parent\tcandidate-carrier-authority\tdistribution/s4-performance/WP8J-AUTHORITY.tsv\t{WP8J_AUTHORITY_SEAL}",
        f"parent\trunner-engine-authority\tdistribution/s4-performance/WP7C-AUTHORITY.tsv\t{WP7C_AUTHORITY_SEAL}",
    ))
    if rows[: len(prefix)] != prefix:
        raise CandidateRunnerError("WP8K authority metadata or parent binding drifted")
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
            or fields[5] != "candidate-measurement-runner"
        ):
            raise CandidateRunnerError("WP8K authority file row is malformed")
        records.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise CandidateRunnerError("WP8K authority inventory drifted")
    return Authority(tuple(records), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        raw = _read_regular(path, record.path)
        mode = stat.S_IFREG | stat.S_IMODE(path.lstat().st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise CandidateRunnerError(f"bound WP8K file drifted: {record.path}")


def _verify_historical_engine(root: Path) -> None:
    contract = wp7c.parse_contract(root / "distribution/s4-performance/WP7C-RUNNER.tsv")
    authority = wp7c.parse_authority(
        root / "distribution/s4-performance/WP7C-AUTHORITY.tsv", contract.seal
    )
    if authority.seal != WP7C_AUTHORITY_SEAL:
        raise CandidateRunnerError("WP7C runner-engine authority drifted")
    transitioned = {relative for *_fields, relative in lt1.TRANSITIONS}
    snapshot = root / "distribution/license-transition/pre-apache"
    for record in authority.files:
        path = snapshot / record.path if record.path in transitioned else root / record.path
        raw = _read_regular(path, f"WP7C historical {record.path}")
        mode = stat.S_IFREG | stat.S_IMODE(path.lstat().st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise CandidateRunnerError(f"WP7C historical authority drifted: {record.path}")


def _static_report(contract: Contract, authority: Authority) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"candidate-host-authority\t{WP8I_AUTHORITY_SEAL}",
        f"candidate-carrier-authority\t{WP8J_AUTHORITY_SEAL}",
        "runner-status\tcandidate-measurement-runner-structurally-admitted",
        "acquisition-status\tretained-eligible-wp8i-host-required",
        "mode\tstatic-no-host-no-clock-no-build-no-execution",
        "claim-status\tnot-admitted",
        "samples-required\t120",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    host = wp8i.validate(root)
    carrier = wp8j.validate(root)
    if host.authority.seal != WP8I_AUTHORITY_SEAL or carrier.authority.seal != WP8J_AUTHORITY_SEAL:
        raise CandidateRunnerError("WP8K current parent authority drifted")
    _verify_historical_engine(root)
    contract = parse_contract(root / "distribution/s4-performance/WP8K-RUNNER.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP8K-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    report, report_root = _static_report(contract, authority)
    return Admission(contract, authority, host, carrier, report, report_root)


def parse_retained_host(path: Path, admission: Admission) -> RetainedHost:
    raw = _read_regular(path, "retained WP8I host attestation", 131_072)
    lines = _canonical(raw, "retained WP8I host attestation", 131_072)
    if lines[0] != wp8i.REPORT_MAGIC or not lines[-1].startswith("report-root\t"):
        raise CandidateRunnerError("retained WP8I report magic or shape drifted")
    root_fields = lines[-1].split("\t")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if (
        len(root_fields) != 2
        or not HASH_RE.fullmatch(root_fields[1])
        or _sha256(wp8i.REPORT_DOMAIN + body) != root_fields[1]
    ):
        raise CandidateRunnerError("retained WP8I report root verification failed")
    fixed = (
        ("contract", WP8I_CONTRACT_SEAL),
        ("authority", WP8I_AUTHORITY_SEAL),
        ("candidate-role-authority", wp8i.WP8H_AUTHORITY_SEAL),
        ("host-protocol-authority", wp8i.WP6_AUTHORITY_SEAL),
        ("protocol-status", "candidate-controlled-host-protocol-admitted"),
        ("host-status", "eligible-ephemeral-observation"),
        ("role", ROLE_NAME),
        ("baseline-role", "naux-residual"),
        ("claim-status", "not-admitted"),
        ("timing-status", "forbidden"),
        ("mode", "host-observation"),
    )
    cursor = 1
    for key, value in fixed:
        if cursor >= len(lines) - 1:
            raise CandidateRunnerError("retained WP8I report ended before fixed rows")
        if lines[cursor] != f"{key}\t{value}":
            raise CandidateRunnerError("retained WP8I authority or eligibility drifted")
        cursor += 1
    if cursor >= len(lines) - 1:
        raise CandidateRunnerError("retained WP8I report ended before fingerprint")
    fingerprint_fields = lines[cursor].split("\t")
    if (
        len(fingerprint_fields) != 2
        or fingerprint_fields[0] != "fingerprint"
        or not HASH_RE.fullmatch(fingerprint_fields[1])
    ):
        raise CandidateRunnerError("retained WP8I fingerprint is malformed")
    cursor += 1
    facts = []
    for _ordinal, expected_name in wp8i.wp6.CONTRACT_FACTS:
        if cursor >= len(lines) - 1:
            raise CandidateRunnerError("retained WP8I report ended before all facts")
        fields = lines[cursor].split("\t")
        if len(fields) != 3 or fields[:2] != ["fact", expected_name]:
            raise CandidateRunnerError("retained WP8I fact order drifted")
        wp8i.wp6._safe_fact(fields[2], expected_name)
        facts.append((expected_name, fields[2]))
        cursor += 1
    if (
        cursor >= len(lines) - 1
        or lines[cursor] != "refusals\t0"
        or cursor + 1 != len(lines) - 1
    ):
        raise CandidateRunnerError("retained WP8I report is not exactly eligible")
    fact_body = b"".join(f"fact\t{key}\t{value}\n".encode() for key, value in facts)
    if _sha256(wp8i.wp6.FINGERPRINT_DOMAIN + fact_body) != fingerprint_fields[1]:
        raise CandidateRunnerError("retained WP8I fact fingerprint mismatch")
    if not COMMIT_RE.fullmatch(dict(facts).get("git-commit", "")):
        raise CandidateRunnerError("retained WP8I commit is malformed")
    return RetainedHost(raw, root_fields[1], fingerprint_fields[1], tuple(facts))


def verify_live_host(root: Path, retained: RetainedHost) -> None:
    observation = wp8i.observe(root.resolve(strict=True), retained.commit)
    if not observation.eligible:
        raise CandidateRunnerError(
            "live host is not eligible under WP8I: " + ",".join(observation.refusals)
        )
    if observation.fingerprint != retained.fingerprint or observation.facts != retained.facts:
        raise CandidateRunnerError("live host differs from retained WP8I attestation")


def build_candidate(
    root: Path,
    directory: Path,
    carrier: wp8j.Admission,
    *,
    cargo_command: str,
    rustc_command: str,
) -> wp7c.RoleBuild:
    cargo = wp7c._resolve_tool(cargo_command, "Cargo")
    rustc = wp7c._resolve_tool(rustc_command, "rustc")
    toolchains = (wp7c._tool_identity("cargo", cargo), wp7c._tool_identity("rustc", rustc))
    target = directory / "cargo-target"
    environment = wp7c._fixed_environment()
    environment.update({"CARGO_TARGET_DIR": os.fspath(target), "RUSTC": os.fspath(rustc)})
    compile_ns = wp7c._run_build(
        [
            os.fspath(cargo), "build", "--locked", "--offline", "--release",
            "-p", "naux", "--example", "naux_s4_register_residency_timing",
            "--target-dir", os.fspath(target),
        ],
        root,
        environment,
        "register-residency timing emitter build",
        silent=False,
    )
    emitter = target / "release/examples/naux_s4_register_residency_timing"
    started = wp7c._raw_ns()
    _report, candidate = wp8j.replay(carrier, emitter)
    specialize_ns = wp7c._raw_ns() - started
    if specialize_ns <= 0:
        raise CandidateRunnerError("candidate specialization interval is non-positive")
    output = directory / ROLE_NAME
    output.mkdir()
    artifacts = []
    for kernel in candidate.kernels:
        ordinal = f"{kernel.record.ordinal:02}"
        path = output / f"{ordinal}-{kernel.record.name}"
        wp7c._write_executable(path, kernel.elf)
        artifacts.append(wp7c._artifact(ROLE_ORDINAL, ordinal, path))
    artifact_tuple = tuple(artifacts)
    if toolchains != (wp7c._tool_identity("cargo", cargo), wp7c._tool_identity("rustc", rustc)):
        raise CandidateRunnerError("candidate toolchain identity drifted during build")
    return wp7c.RoleBuild(
        ROLE_ORDINAL,
        ROLE_NAME,
        "candidate-isolated",
        wp7c.aggregate_binary_identity(artifact_tuple),
        wp7c.aggregate_toolchain_identity(toolchains),
        compile_ns,
        specialize_ns,
        artifact_tuple,
        toolchains,
    )


def verify_build_identity(build: wp7c.RoleBuild) -> None:
    if (
        build.ordinal != ROLE_ORDINAL
        or build.name != ROLE_NAME
        or build.path_status != "candidate-isolated"
    ):
        raise CandidateRunnerError("candidate build role identity drifted")
    artifacts = tuple(
        wp7c._artifact(artifact.role, artifact.kernel, artifact.path)
        for artifact in build.artifacts
    )
    if (
        artifacts != build.artifacts
        or wp7c.aggregate_binary_identity(artifacts) != build.binary_hash
    ):
        raise CandidateRunnerError("candidate artifact identity drifted")
    toolchains = tuple(
        wp7c._tool_identity(tool.name, Path(tool.executable_path))
        for tool in build.toolchains
    )
    if (
        toolchains != build.toolchains
        or wp7c.aggregate_toolchain_identity(toolchains) != build.toolchain_hash
    ):
        raise CandidateRunnerError("candidate toolchain identity drifted")


def decode_candidate_record(raw: bytes, kernel: str) -> wp7c.CarrierResult:
    if len(raw) != RESULT_BYTES or raw[:8] != RESULT_MAGIC:
        raise CandidateRunnerError("candidate result length or magic drifted")
    kernel_map = {ordinal: (name, oracle) for ordinal, name, oracle in KERNELS}
    if kernel not in kernel_map:
        raise CandidateRunnerError("unknown candidate kernel ordinal")
    result = wp7c.CarrierResult(*struct.unpack("<QqQQQQ", raw[8:]))
    _name, oracle = kernel_map[kernel]
    expected = (
        ("kernel", result.kernel_ordinal, int(kernel)),
        ("checksum", result.checksum, oracle),
        ("outer", result.outer, REPS),
        ("inner", result.inner, N),
        ("owner", result.owner, ROLE_OWNER),
    )
    for label, observed, required in expected:
        if observed != required:
            raise CandidateRunnerError(
                f"candidate {kernel} {label} drifted: expected {required}, observed {observed}"
            )
    if result.duration_ns <= 0:
        raise CandidateRunnerError("candidate duration is non-positive")
    return result


def execute_candidate(artifact: wp7c.Artifact) -> tuple[wp7c.CarrierResult, int, int]:
    expected = wp7c._artifact(artifact.role, artifact.kernel, artifact.path)
    if artifact.role != ROLE_ORDINAL or expected.sha256 != artifact.sha256 or expected.size != artifact.size:
        raise CandidateRunnerError("candidate artifact changed before execution")
    stdout_read, stdout_write = os.pipe2(os.O_CLOEXEC)
    stderr_read, stderr_write = os.pipe2(os.O_CLOEXEC)
    started = wp7c._raw_ns()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - observed by the parent through wait4.
        try:
            null = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            os.dup2(null, 0)
            os.dup2(stdout_write, 1)
            os.dup2(stderr_write, 2)
            for descriptor in (null, stdout_read, stdout_write, stderr_read, stderr_write):
                if descriptor > 2:
                    os.close(descriptor)
            os.execve(os.fspath(artifact.path), [os.fspath(artifact.path)], wp7c._fixed_environment())
        except BaseException:
            os._exit(127)
    os.close(stdout_write)
    os.close(stderr_write)
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    status = None
    usage = None
    timed_out = False
    try:
        for descriptor, name in ((stdout_read, "stdout"), (stderr_read, "stderr")):
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ, name)
        deadline = started + PROCESS_TIMEOUT_SECONDS * 1_000_000_000
        while status is None or selector.get_map():
            for key, _mask in selector.select(0.02):
                try:
                    chunk = os.read(key.fd, 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    os.close(key.fd)
                    continue
                target = stdout if key.data == "stdout" else stderr
                target.extend(chunk)
                if len(stdout) > RESULT_BYTES or len(stderr) > 65_536:
                    raise CandidateRunnerError("candidate output exceeds its exact extent")
            if status is None:
                waited_pid, waited_status, waited_usage = os.wait4(pid, os.WNOHANG)
                if waited_pid == pid:
                    status, usage = waited_status, waited_usage
            if status is None and wp7c._raw_ns() >= deadline:
                timed_out = True
                os.kill(pid, signal.SIGKILL)
                _waited_pid, status, usage = os.wait4(pid, 0)
        ended = wp7c._raw_ns()
    except BaseException:
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.wait4(pid, 0)
            except ChildProcessError:
                pass
        raise
    finally:
        for key in tuple(selector.get_map().values()):
            selector.unregister(key.fd)
            os.close(key.fd)
        selector.close()
    if (
        timed_out
        or status is None
        or usage is None
        or not os.WIFEXITED(status)
        or os.WEXITSTATUS(status) != 0
        or stderr
    ):
        raise CandidateRunnerError("candidate carrier timed out, failed, or emitted stderr")
    envelope_ns = ended - started
    rss_bytes = int(usage.ru_maxrss) * 1024
    if envelope_ns <= 0 or rss_bytes <= 0:
        raise CandidateRunnerError("candidate envelope or wait4 RSS is non-positive")
    return decode_candidate_record(bytes(stdout), artifact.kernel), envelope_ns, rss_bytes


def collect_invocations(build: wp7c.RoleBuild) -> wp7c.AcquisitionData:
    warmups = []
    samples = []
    for artifact in build.artifacts:
        cumulative = 0
        ordinal = 0
        while cumulative < WARMUP_MINIMUM_NS:
            ordinal += 1
            if ordinal > MAX_WARMUP_INVOCATIONS:
                raise CandidateRunnerError("candidate warmup invocation ceiling reached")
            result, envelope, rss = execute_candidate(artifact)
            invocation = wp7c.Invocation(
                ROLE_ORDINAL, artifact.kernel, ordinal, result.duration_ns,
                result.checksum, build.path_status, envelope, rss,
            )
            if invocation.overhead_ns <= 0:
                raise CandidateRunnerError("candidate warmup envelope does not contain runtime")
            warmups.append(invocation)
            cumulative += result.duration_ns
        for sample_ordinal in range(1, SAMPLE_COUNT + 1):
            result, envelope, rss = execute_candidate(artifact)
            invocation = wp7c.Invocation(
                ROLE_ORDINAL, artifact.kernel, sample_ordinal, result.duration_ns,
                result.checksum, build.path_status, envelope, rss,
            )
            if invocation.overhead_ns <= 0:
                raise CandidateRunnerError("candidate sample envelope does not contain runtime")
            samples.append(invocation)
    if len(samples) != len(KERNELS) * SAMPLE_COUNT:
        raise CandidateRunnerError("candidate sample extent drifted")
    return wp7c.AcquisitionData((build,), tuple(warmups), tuple(samples))


def build_raw_session(
    runner: Admission,
    retained: RetainedHost,
    data: wp7c.AcquisitionData,
) -> tuple[bytes, str]:
    build = data.builds[0]
    rows = [
        SESSION_MAGIC,
        f"meta\trunner-authority\t{runner.authority.seal}",
        f"meta\thost-attestation\t{retained.report_root}",
        f"meta\tsource-commit\t{retained.commit}",
        f"meta\tcarrier-authority\t{WP8J_AUTHORITY_SEAL}",
        f"meta\trole\t{ROLE_NAME}",
        "meta\tclaim-status\tnot-admitted",
        f"build\t{build.binary_hash}\t{build.toolchain_hash}\t{build.compile_ns}\t{build.specialize_ns}\t{build.code_size}",
        f"warmups\t{len(data.warmups)}",
    ]
    rows.extend(
        f"warmup\t{item.kernel}\t{item.ordinal}\t{item.duration_ns}\t{item.checksum}\t{item.envelope_ns}\t{item.rss_bytes}"
        for item in data.warmups
    )
    rows.append(f"samples\t{len(data.samples)}")
    rows.extend(
        f"sample\t{item.kernel}\t{item.ordinal}\t{item.duration_ns}\t{item.checksum}\t{item.envelope_ns}\t{item.rss_bytes}"
        for item in data.samples
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(SESSION_DOMAIN + body)
    return body + f"session-root\t{root}\n".encode(), root


def publish_bundle(
    root: Path,
    output: Path,
    runner: Admission,
    retained: RetainedHost,
    data: wp7c.AcquisitionData,
    session: bytes,
    session_root: str,
    host_attestation_path: Path,
) -> str:
    verify_build_identity(data.builds[0])
    output = wp7c._checked_output(root, output)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.stage-", dir=output.parent))
    published = False
    try:
        build = data.builds[0]
        tool_rows = [
            TOOLCHAIN_MAGIC,
            f"meta\trunner-authority\t{runner.authority.seal}",
            f"meta\tsource-commit\t{retained.commit}",
            "meta\tclaim-status\tnot-admitted",
        ]
        for ordinal, tool in enumerate(build.toolchains, 1):
            tool_rows.append(
                f"tool\t{ordinal:02}\t{tool.name}\t{tool.executable_path}\t"
                f"{tool.executable_hash}\t{tool.version_hash}\t{tool.version_hex}"
            )
        tool_body = b"".join(f"{row}\n".encode() for row in tool_rows)
        tool_receipt = tool_body + f"toolchain-root\t{_sha256(TOOLCHAIN_DOMAIN + tool_body)}\n".encode()
        reproduction = (
            "NAUX-S4-REGISTER-RESIDENCY-REPRODUCTION\t1\n"
            f"source-commit\t{retained.commit}\n"
            f"runner-authority\t{runner.authority.seal}\n"
            f"host-attestation-root\t{retained.report_root}\n"
            f"original-host-attestation\t{host_attestation_path.resolve(strict=True)}\n"
            "policy\tnew-eligible-attestation-and-new-output-required-for-each-run\n"
        ).encode()
        files = [
            ("HOST-ATTESTATION.tsv", retained.raw, 0o600),
            ("RAW-SESSION.tsv", session, 0o600),
            ("TOOLCHAINS.tsv", tool_receipt, 0o600),
            ("REPRODUCE.tsv", reproduction, 0o600),
        ]
        kernel_names = {ordinal: name for ordinal, name, _oracle in KERNELS}
        for artifact in build.artifacts:
            files.append((
                f"artifacts/{artifact.kernel}-{kernel_names[artifact.kernel]}",
                artifact.path.read_bytes(),
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
    retained = parse_retained_host(host_attestation, runner)
    checked_output = wp7c._checked_output(root, output)
    verify_live_host(root, retained)
    with tempfile.TemporaryDirectory(prefix="naux-s4-wp8k-build-") as directory_name:
        build = build_candidate(
            root, Path(directory_name), runner.carrier,
            cargo_command=cargo_command, rustc_command=rustc_command,
        )
        verify_live_host(root, retained)
        data = collect_invocations(build)
        verify_build_identity(build)
        verify_live_host(root, retained)
        session, session_root = build_raw_session(runner, retained, data)
        bundle_root = publish_bundle(
            root, checked_output, runner, retained, data, session, session_root,
            host_attestation,
        )
    rows = (
        REPORT_MAGIC,
        f"contract\t{runner.contract.seal}",
        f"authority\t{runner.authority.seal}",
        f"host-attestation\t{retained.report_root}",
        f"session-root\t{session_root}",
        f"bundle-root\t{bundle_root}",
        "mode\texplicit-controlled-candidate-acquisition",
        "samples\t120",
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
                arguments.root, arguments.host_attestation, arguments.output,
                cargo_command=arguments.cargo, rustc_command=arguments.rustc,
            )
            sys.stdout.buffer.write(report)
        else:
            sys.stdout.buffer.write(validate(arguments.root).static_report)
        return 0
    except (
        CandidateRunnerError,
        wp7c.RunnerError,
        wp8i.CandidateHostError,
        wp8j.CandidateTimingError,
        OSError,
        subprocess.SubprocessError,
        ValueError,
    ) as error:
        print(f"S4-WP8K validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
