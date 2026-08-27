#!/usr/bin/env python3
"""Validate the clock-free S4-WP7A evidence law and replay candidates."""

from __future__ import annotations

import argparse
import hashlib
import math
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_controlled_host as wp6


CONTRACT_MAGIC = "NAUX-S4-MEASUREMENT-EVIDENCE-LAW\t1"
AUTHORITY_MAGIC = "NAUX-S4-MEASUREMENT-EVIDENCE-LAW-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-MEASUREMENT-EVIDENCE-LAW-REPORT\t1"
EVIDENCE_MAGIC = "NAUX-S4-MEASUREMENT-EVIDENCE\t1"
CONTRACT_DOMAIN = b"NAUX:s4-measurement-evidence-law:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-measurement-evidence-law:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-measurement-evidence-law:report:v1\0"
EVIDENCE_DOMAIN = b"NAUX:s4-measurement-evidence:candidate:v1\0"
WP4_AUTHORITY_SEAL = "bda4409f32e1afe162b68401529d127cf4a77077df000826823d2660ee4ade26"
WP5F_AUTHORITY_SEAL = "702ba39892da6817ce5ed6d0c23c4a454b4adeb7e5053cf8d10b1cc21cba1fc0"
WP6_AUTHORITY_SEAL = "9cc57ce48ec67d92724b417d43d9556e0e8446e5dfe2770b3d68ffd5dfe49b59"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
PATH_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9._/-]*\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")
POSITIVE_RE = re.compile(r"[1-9][0-9]*\Z")
INT_RE = re.compile(r"0|-?[1-9][0-9]*\Z")

CONTRACT_METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-measurement-boundary", WP4_AUTHORITY_SEAL),
    ("parent-residual-role", WP5F_AUTHORITY_SEAL),
    ("parent-host-protocol", WP6_AUTHORITY_SEAL),
    ("law-status", "evidence-law-admitted"),
    ("carrier-status", "required-not-admitted"),
    ("host-attestation-status", "required-not-retained"),
    ("runner-status", "required-not-admitted"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("clock-source", "clock-monotonic-raw"),
    (
        "runtime-region",
        "allocation-initialization-kernel-checksum-validation-teardown",
    ),
    ("clock-placement", "inside-role-before-allocation-after-teardown"),
    ("minimum-warmup-ns", "100000000"),
    ("measured-samples", "30"),
    ("sample-policy", "ordered-complete-no-drop-no-retry"),
    ("statistics", "median-rational-p95-nearest-rank-cv-square-rational"),
    ("maximum-cv-percent", "5"),
)
ROLES = (
    ("01", "naux-residual", "native-clean"),
    ("02", "c-generic", "reference-clean"),
    ("03", "c-specialized", "reference-clean"),
)
KERNELS = (
    ("01", "sum-dense", 6710476800),
    ("02", "branch-mix", -69189632),
    ("03", "dot-product", 73294064435200),
    ("04", "list-update", 6730547200),
)
FIELDS = (
    ("01", "role-binary", "sha256"),
    ("02", "role-toolchain", "sha256"),
    ("03", "compile-ns", "separate-positive"),
    ("04", "specialize-ns", "separate-naux-positive-c-zero"),
    ("05", "startup-ns", "separate-positive"),
    ("06", "peak-rss-bytes", "separate-positive"),
    ("07", "code-size-bytes", "separate-positive"),
    ("08", "warmup-ns", "per-role-kernel-minimum"),
    ("09", "runtime-ns", "per-ordered-sample-positive"),
    ("10", "checksum", "per-warmup-and-sample-exact"),
    ("11", "path-status", "per-warmup-and-sample-exact"),
    ("12", "median", "canonical-reduced-rational"),
    ("13", "p95", "nearest-rank-integer"),
    ("14", "cv-square", "canonical-reduced-rational"),
)
GATES = (
    ("01", "parent-authorities", "required", "exact-wp4-wp5f-wp6"),
    ("02", "instrumentation-authority", "required", "inside-role-equal-runtime-boundary"),
    ("03", "host-attestation", "required", "retained-exact-controlled-host"),
    ("04", "runner-authority", "required", "exact-evidence-acquisition"),
    ("05", "role-identity", "required", "exact-binary-and-toolchain-hashes"),
    ("06", "semantic-parity", "required", "every-warmup-and-sample"),
    ("07", "raw-completeness", "required", "three-roles-four-kernels-thirty-samples"),
    ("08", "cost-separation", "required", "compile-specialize-startup-runtime-memory-code-size"),
    ("09", "arithmetic-replay", "required", "exact-median-p95-cv-square"),
    ("10", "variance", "required", "cv-not-greater-than-five-percent"),
)
BLOCKERS = (
    ("01", "instrumented-carriers-unavailable"),
    ("02", "retained-controlled-host-attestation-unavailable"),
    ("03", "measurement-runner-unavailable"),
    ("04", "raw-measurement-evidence-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP7A"),
    ("authority-id", "s4-measurement-evidence-law-v1"),
    ("law-status", "evidence-law-admitted"),
    ("claim-status", "not-admitted"),
    ("timing-status", "forbidden"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-measurement-evidence.yml",
    "distribution/s4-performance/WP7A-EVIDENCE.tsv",
    "distribution/s4-performance/WP7A-NONCLAIMS.md",
    "distribution/s4-performance/WP7A-README.md",
    "scripts/s4_measurement_evidence.py",
    "scripts/tests/test_s4_measurement_evidence_replay.py",
    "scripts/tests/test_s4_measurement_evidence_static.py",
)


class EvidenceError(RuntimeError):
    """A fail-closed S4-WP7A evidence-law error."""


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
    static_report: bytes
    static_root: str


@dataclass(frozen=True)
class Statistic:
    role: str
    kernel: str
    median_num: int
    median_den: int
    p95: int
    cv2_num: int
    cv2_den: int
    stable: bool


@dataclass(frozen=True)
class Candidate:
    statistics: tuple[Statistic, ...]
    evidence_root: str

    @property
    def variance_gate(self) -> bool:
        return all(statistic.stable for statistic in self.statistics)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(raw: bytes, label: str, maximum: int = 2_000_000) -> list[str]:
    if not raw or len(raw) > maximum or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise EvidenceError(f"{label} has invalid extent or encoding")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{label} is not UTF-8") from error
    lines = text.splitlines()
    if any(not line for line in lines):
        raise EvidenceError(f"{label} contains a blank row")
    return lines


def _sealed_lines(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(f"{path.name} is not a regular file")
    lines = _canonical(path.read_bytes(), path.name)
    return _verify_sealed_lines(lines, magic, domain, path.name)


def _verify_sealed_lines(
    lines: list[str], magic: str, domain: bytes, label: str
) -> tuple[list[str], str]:
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise EvidenceError(f"{label} shape or magic drifted")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise EvidenceError(f"{label} seal row is malformed")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if _sha256(domain + body) != fields[1]:
        raise EvidenceError(f"{label} seal verification failed")
    return lines, fields[1]


def _take(lines: list[str], index: int, tag: str, width: int) -> tuple[list[tuple[str, ...]], int]:
    rows: list[tuple[str, ...]] = []
    while index < len(lines) - 1 and lines[index].startswith(f"{tag}\t"):
        fields = lines[index].split("\t")
        if len(fields) != width:
            raise EvidenceError(f"WP7A {tag} row is malformed")
        rows.append(tuple(fields[1:]))
        index += 1
    return rows, index


def parse_contract(path: Path) -> Contract:
    lines, seal = _sealed_lines(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    index = 1
    metadata, index = _take(lines, index, "meta", 3)
    roles, index = _take(lines, index, "role", 4)
    kernels, index = _take(lines, index, "kernel", 4)
    fields, index = _take(lines, index, "field", 4)
    gates, index = _take(lines, index, "gate", 5)
    blockers, index = _take(lines, index, "blocker", 3)
    expected_kernels = tuple((ordinal, name, str(oracle)) for ordinal, name, oracle in KERNELS)
    if tuple(metadata) != CONTRACT_METADATA:
        raise EvidenceError("WP7A contract metadata drifted")
    if tuple(roles) != ROLES or tuple(kernels) != expected_kernels:
        raise EvidenceError("WP7A role or kernel set drifted")
    if tuple(fields) != FIELDS or tuple(gates) != GATES:
        raise EvidenceError("WP7A field or gate set drifted")
    if tuple(blockers) != BLOCKERS or index != len(lines) - 1:
        raise EvidenceError("WP7A blocker set or extent drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    lines, seal = _sealed_lines(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    index = 1
    metadata, index = _take(lines, index, "meta", 3)
    if tuple(metadata) != AUTHORITY_METADATA:
        raise EvidenceError("WP7A authority metadata drifted")
    expected_links = (
        f"component\tevidence-law\tdistribution/s4-performance/WP7A-EVIDENCE.tsv\t{contract_seal}",
        f"parent\tmeasurement-boundary-authority\tdistribution/s4-performance/WP4-AUTHORITY.tsv\t{WP4_AUTHORITY_SEAL}",
        f"parent\tresidual-role-authority\tdistribution/s4-performance/WP5F-AUTHORITY.tsv\t{WP5F_AUTHORITY_SEAL}",
        f"parent\tcontrolled-host-protocol-authority\tdistribution/s4-performance/WP6-AUTHORITY.tsv\t{WP6_AUTHORITY_SEAL}",
    )
    if tuple(lines[index : index + 4]) != expected_links:
        raise EvidenceError("WP7A component or parent binding drifted")
    index += 4
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
            or fields[5] != "evidence-law"
        ):
            raise EvidenceError("WP7A authority file row is malformed")
        files.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
        index += 1
    if tuple(record.path for record in files) != EXPECTED_FILES:
        raise EvidenceError("WP7A authority file inventory drifted")
    return Authority(tuple(files), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise EvidenceError(f"WP7A bound file is not regular: {record.path}")
        raw = path.read_bytes()
        mode = stat.S_IFREG | stat.S_IMODE(metadata.st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise EvidenceError(f"WP7A bound file drifted: {record.path}")


def _verify_clock_free_boundary(root: Path) -> None:
    workflow = (root / ".github/workflows/s4-measurement-evidence.yml").read_text()
    for token in ("scripts/s4_measurement_evidence.py", "test_s4_measurement_evidence_static", "test_s4_measurement_evidence_replay"):
        if token not in workflow:
            raise EvidenceError("WP7A workflow omits a clock-free gate")
    combined = "\n".join((root / relative).read_text() for relative in EXPECTED_FILES)
    forbidden = (
        "import " + "time",
        "import " + "subprocess",
        "import " + "resource",
        "." + "monotonic(",
        "." + "perf_counter(",
        "." + "time_ns(",
        "." + "clock_gettime(",
        "Popen" + "(",
        "subprocess" + ".run(",
    )
    if any(token in combined for token in forbidden):
        raise EvidenceError("WP7A source can acquire time or execute a workload")
    expected = {"WP7A-AUTHORITY.tsv", "WP7A-EVIDENCE.tsv", "WP7A-NONCLAIMS.md", "WP7A-README.md"}
    actual = {
        path.name
        for path in (root / "distribution/s4-performance").glob("WP7A-*")
        if path.is_file()
    }
    if actual != expected:
        raise EvidenceError("unexpected WP7A distribution artifact")


def _static_report(contract: Contract, authority: Authority) -> bytes:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"parent-host-protocol\t{WP6_AUTHORITY_SEAL}",
        "law-status\tevidence-law-admitted",
        "claim-status\tnot-admitted",
        "timing-status\tforbidden",
        "mode\tstatic-authority",
        "roles\t3",
        "kernels\t4",
        "samples-required\t360",
        "blockers\t4",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    return body + f"report-root\t{_sha256(REPORT_DOMAIN + body)}\n".encode()


def validate(root: Path) -> Admission:
    root = root.resolve()
    host = wp6.validate(root)
    if host.authority.seal != WP6_AUTHORITY_SEAL:
        raise EvidenceError("WP6 parent authority drifted")
    contract = parse_contract(root / "distribution/s4-performance/WP7A-EVIDENCE.tsv")
    authority = parse_authority(
        root / "distribution/s4-performance/WP7A-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    _verify_clock_free_boundary(root)
    report = _static_report(contract, authority)
    report_root = report.decode().split("report-root\t", 1)[1].strip()
    return Admission(contract, authority, report, report_root)


def _positive(value: str, label: str) -> int:
    if not POSITIVE_RE.fullmatch(value):
        raise EvidenceError(f"{label} is not a canonical positive integer")
    return int(value)


def _unsigned(value: str, label: str) -> int:
    if not UINT_RE.fullmatch(value):
        raise EvidenceError(f"{label} is not a canonical unsigned integer")
    return int(value)


def _integer(value: str, label: str) -> int:
    if not INT_RE.fullmatch(value):
        raise EvidenceError(f"{label} is not a canonical integer")
    return int(value)


def _reduced(numerator: int, denominator: int) -> tuple[int, int]:
    if numerator < 0 or denominator <= 0:
        raise EvidenceError("invalid exact rational")
    divisor = math.gcd(numerator, denominator)
    return numerator // divisor, denominator // divisor


def derive_statistic(role: str, kernel: str, durations: tuple[int, ...]) -> Statistic:
    if len(durations) != 30 or any(value <= 0 for value in durations):
        raise EvidenceError("statistic input must contain thirty positive samples")
    ordered = sorted(durations)
    median_num, median_den = _reduced(ordered[14] + ordered[15], 2)
    p95 = ordered[28]
    total = sum(durations)
    spread = len(durations) * sum(value * value for value in durations) - total * total
    cv2_num, cv2_den = _reduced(spread, total * total)
    stable = 400 * cv2_num <= cv2_den
    return Statistic(role, kernel, median_num, median_den, p95, cv2_num, cv2_den, stable)


def _candidate_lines(raw: bytes) -> tuple[list[str], str]:
    lines = _canonical(raw, "measurement evidence candidate")
    if lines[0] != EVIDENCE_MAGIC or not lines[-1].startswith("evidence-root\t"):
        raise EvidenceError("measurement evidence shape or magic drifted")
    fields = lines[-1].split("\t")
    if len(fields) != 2 or not HASH_RE.fullmatch(fields[1]):
        raise EvidenceError("measurement evidence root is malformed")
    body = b"".join(f"{line}\n".encode() for line in lines[:-1])
    if _sha256(EVIDENCE_DOMAIN + body) != fields[1]:
        raise EvidenceError("measurement evidence root verification failed")
    return lines, fields[1]


def replay_candidate(
    raw: bytes,
    admission: Admission,
    *,
    carrier_authority: str,
    host_attestation: str,
    runner_authority: str,
) -> Candidate:
    for value, label in (
        (carrier_authority, "carrier authority"),
        (host_attestation, "host attestation"),
        (runner_authority, "runner authority"),
    ):
        if not HASH_RE.fullmatch(value):
            raise EvidenceError(f"{label} is malformed")
    lines, evidence_root = _candidate_lines(raw)
    index = 1
    metadata, index = _take(lines, index, "meta", 3)
    if len(metadata) != 11:
        raise EvidenceError("measurement evidence metadata extent drifted")
    metadata_map = dict(metadata)
    if len(metadata_map) != len(metadata):
        raise EvidenceError("duplicate measurement evidence metadata")
    expected_metadata = {
        "contract": admission.contract.seal,
        "evidence-law-authority": admission.authority.seal,
        "carrier-authority": carrier_authority,
        "host-attestation": host_attestation,
        "runner-authority": runner_authority,
        "clock-source": "clock-monotonic-raw",
        "runtime-region": "allocation-initialization-kernel-checksum-validation-teardown",
        "sample-policy": "ordered-complete-no-drop-no-retry",
        "sample-count": "30",
        "claim-status": "not-admitted",
    }
    if any(metadata_map.get(key) != value for key, value in expected_metadata.items()):
        raise EvidenceError("measurement evidence authority or policy metadata drifted")
    if not COMMIT_RE.fullmatch(metadata_map.get("source-commit", "")):
        raise EvidenceError("measurement evidence source commit is malformed")

    role_rows, index = _take(lines, index, "role", 6)
    if len(role_rows) != len(ROLES):
        raise EvidenceError("measurement evidence role count drifted")
    for actual, expected in zip(role_rows, ROLES, strict=True):
        ordinal, name, binary_hash, toolchain_hash, path_status = actual
        if (ordinal, name, path_status) != expected:
            raise EvidenceError("measurement evidence role identity drifted")
        if not HASH_RE.fullmatch(binary_hash) or not HASH_RE.fullmatch(toolchain_hash):
            raise EvidenceError("measurement evidence role hash is malformed")

    cost_rows, index = _take(lines, index, "cost", 7)
    if len(cost_rows) != len(ROLES):
        raise EvidenceError("measurement evidence cost count drifted")
    for actual, expected in zip(cost_rows, ROLES, strict=True):
        ordinal, compile_ns, specialize_ns, startup_ns, peak_rss, code_size = actual
        if ordinal != expected[0]:
            raise EvidenceError("measurement evidence cost role order drifted")
        _positive(compile_ns, "compile cost")
        specialization = _unsigned(specialize_ns, "specialization cost")
        if (ordinal == "01") != (specialization > 0):
            raise EvidenceError("measurement evidence specialization cost drifted")
        _positive(startup_ns, "startup cost")
        _positive(peak_rss, "peak RSS")
        _positive(code_size, "code size")

    expected_pairs = tuple(
        (role[0], kernel[0], kernel[2], role[2])
        for role in ROLES
        for kernel in KERNELS
    )
    warmup_rows, index = _take(lines, index, "warmup", 6)
    if len(warmup_rows) != len(expected_pairs):
        raise EvidenceError("measurement evidence warmup count drifted")
    for actual, expected in zip(warmup_rows, expected_pairs, strict=True):
        role, kernel, duration, checksum, path_status = actual
        if (role, kernel, _integer(checksum, "warmup checksum"), path_status) != expected:
            raise EvidenceError("measurement evidence warmup identity or parity drifted")
        if _positive(duration, "warmup duration") < 100_000_000:
            raise EvidenceError("measurement evidence warmup is shorter than 100 ms")

    sample_rows, index = _take(lines, index, "sample", 7)
    if len(sample_rows) != len(expected_pairs) * 30:
        raise EvidenceError("measurement evidence raw sample count drifted")
    duration_groups: dict[tuple[str, str], list[int]] = {
        (role, kernel): [] for role, kernel, _oracle, _status in expected_pairs
    }
    cursor = 0
    for role, kernel, oracle, path_status in expected_pairs:
        for sample_index in range(1, 31):
            actual = sample_rows[cursor]
            cursor += 1
            actual_role, actual_kernel, ordinal, duration, checksum, actual_status = actual
            if (
                actual_role != role
                or actual_kernel != kernel
                or ordinal != f"{sample_index:02}"
                or _integer(checksum, "sample checksum") != oracle
                or actual_status != path_status
            ):
                raise EvidenceError("measurement evidence sample order, parity, or path drifted")
            duration_groups[(role, kernel)].append(_positive(duration, "runtime sample"))

    derived = tuple(
        derive_statistic(role, kernel, tuple(duration_groups[(role, kernel)]))
        for role, kernel, _oracle, _status in expected_pairs
    )
    statistic_rows, index = _take(lines, index, "stat", 9)
    if len(statistic_rows) != len(derived) or index != len(lines) - 1:
        raise EvidenceError("measurement evidence statistic count or extent drifted")
    for actual, expected in zip(statistic_rows, derived, strict=True):
        role, kernel, median_num, median_den, p95, cv2_num, cv2_den, stable = actual
        observed = (
            role,
            kernel,
            _unsigned(median_num, "median numerator"),
            _positive(median_den, "median denominator"),
            _positive(p95, "p95"),
            _unsigned(cv2_num, "CV square numerator"),
            _positive(cv2_den, "CV square denominator"),
            stable,
        )
        wanted = (
            expected.role,
            expected.kernel,
            expected.median_num,
            expected.median_den,
            expected.p95,
            expected.cv2_num,
            expected.cv2_den,
            "pass" if expected.stable else "fail",
        )
        if observed != wanted:
            raise EvidenceError("measurement evidence derived arithmetic drifted")
        if math.gcd(observed[2], observed[3]) != 1 or math.gcd(observed[5], observed[6]) != 1:
            raise EvidenceError("measurement evidence rational is not canonical")
    return Candidate(derived, evidence_root)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    try:
        admission = validate(arguments.root)
        sys.stdout.buffer.write(admission.static_report)
        return 0
    except (EvidenceError, wp6.HostControlError, OSError) as error:
        print(f"S4-WP7A validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
