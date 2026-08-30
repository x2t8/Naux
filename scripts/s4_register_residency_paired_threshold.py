#!/usr/bin/env python3
"""Validate or evaluate the S4-WP8O paired threshold-candidate law."""

from __future__ import annotations

import argparse
import hashlib
import math
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_paired_evidence as wp8n


CONTRACT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PAIRED-THRESHOLD-CONTRACT\t1"
AUTHORITY_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PAIRED-THRESHOLD-AUTHORITY\t1"
REPORT_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PAIRED-THRESHOLD-REPORT\t1"
CANDIDATE_MAGIC = "NAUX-S4-REGISTER-RESIDENCY-PAIRED-THRESHOLD-CANDIDATE\t1"
CONTRACT_DOMAIN = b"NAUX:s4-register-residency-paired-threshold:contract:v1\0"
AUTHORITY_DOMAIN = b"NAUX:s4-register-residency-paired-threshold:authority:v1\0"
REPORT_DOMAIN = b"NAUX:s4-register-residency-paired-threshold:report:v1\0"
CANDIDATE_DOMAIN = b"NAUX:s4-register-residency-paired-threshold:candidate:v1\0"
CONTRACT_SEAL = "f9814b36ed6eb1beea99d78e68215866a8ce09852423ab2db414a6e87a1878ac"
WP8N_AUTHORITY_SEAL = "b616acf7d4b641bd753b129180dfc5aa26a42cc1bd15377f36c19798f3e08c4f"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MODE_RE = re.compile(r"100(?:644|755)\Z")
UINT_RE = re.compile(r"0|[1-9][0-9]*\Z")

MIN_EFFECTIVE_PAIRS = 24
SIGN_ALPHA_NUM = 1
SIGN_ALPHA_DEN = 100
MIN_SPEEDUP_NUM = 21
MIN_SPEEDUP_DEN = 20

METADATA = (
    ("policy-version", "1.0.0"),
    ("parent-paired-evidence-authority", WP8N_AUTHORITY_SEAL),
    ("status", "paired-threshold-structurally-admitted"),
    ("input", "exact-wp8n-paired-evidence-v1"),
    ("clock-policy", "forbidden"),
    ("execution-policy", "forbidden"),
    ("arithmetic", "exact-integer-rational-cross-products"),
    ("tie-policy", "disclosed-and-excluded-from-effective-sign-pairs"),
    ("minimum-effective-pairs", str(MIN_EFFECTIVE_PAIRS)),
    ("one-sided-sign-alpha", f"{SIGN_ALPHA_NUM}/{SIGN_ALPHA_DEN}"),
    ("minimum-total-speedup", f"{MIN_SPEEDUP_NUM}/{MIN_SPEEDUP_DEN}"),
    ("paired-median-policy", "strictly-negative-candidate-minus-baseline"),
    ("family-policy", "all-four-kernels-must-pass-every-gate"),
    ("result", "paired-threshold-candidate-only"),
    ("claim-status", "not-admitted"),
    ("target", "x86_64-unknown-linux-gnu"),
)
GATES = (
    ("01", "parent", "required", "exact-wp8n-authority-and-evidence-replay"),
    ("02", "bundle", "required", "exact-wp8m-paired-bundle-v1"),
    ("03", "coverage", "required", "at-least24-nontied-pairs-per-kernel"),
    ("04", "direction", "required", "strictly-negative-paired-median-per-kernel"),
    ("05", "sign-tail", "required", "exact-one-sided-binomial-tail-at-most1-over100"),
    ("06", "magnitude", "required", "baseline-total-over-candidate-total-at-least21-over20"),
    ("07", "family", "required", "all-four-kernels-pass-all-gates"),
    ("08", "claim-boundary", "required", "candidate-never-self-admits-claim"),
)
CLOSURES = (
    ("01", "paired-inference-threshold-authority-unavailable", "closed", "wp8o-exact-law"),
)
BLOCKERS = (
    ("01", "eligible-paired-raw-bundle-unavailable"),
    ("02", "performance-claim-authority-unavailable"),
)
AUTHORITY_METADATA = (
    ("scope", "S4"),
    ("work-package", "S4-WP8O"),
    ("authority-id", "s4-register-residency-paired-threshold-v1"),
    ("status", "paired-threshold-structurally-admitted"),
    ("claim-status", "not-admitted"),
    ("execution-policy", "forbidden"),
    ("file-count", "7"),
)
EXPECTED_FILES = (
    ".github/workflows/s4-register-residency-paired-threshold.yml",
    "distribution/s4-performance/WP8O-PAIRED-THRESHOLD.tsv",
    "distribution/s4-performance/WP8O-NONCLAIMS.md",
    "distribution/s4-performance/WP8O-README.md",
    "scripts/s4_register_residency_paired_threshold.py",
    "scripts/tests/test_s4_register_residency_paired_threshold_replay.py",
    "scripts/tests/test_s4_register_residency_paired_threshold_static.py",
)


class PairedThresholdError(RuntimeError):
    """A fail-closed S4-WP8O validation or evaluation error."""


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
    evidence: wp8n.Admission
    static_report: bytes
    report_root: str


@dataclass(frozen=True)
class KernelDecision:
    ordinal: str
    name: str
    sample_pairs: int
    effective_pairs: int
    wins: int
    ties: int
    losses: int
    sign_tail_num: int
    sign_tail_den: int
    total_ratio_num: int
    total_ratio_den: int
    delta_median_num: int
    delta_median_den: int
    coverage_pass: bool
    direction_pass: bool
    sign_pass: bool
    magnitude_pass: bool
    kernel_pass: bool


@dataclass(frozen=True)
class Evaluation:
    replay: wp8n.Replay
    decisions: tuple[KernelDecision, ...]
    report: bytes
    candidate_root: str
    threshold_pass: bool


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(path: Path, magic: str, domain: bytes) -> tuple[list[str], str]:
    raw = wp8n._read_regular(path, path.name)
    lines = wp8n._canonical(raw, path.name)
    if lines[0] != magic or not lines[-1].startswith("seal\t"):
        raise PairedThresholdError(f"{path.name} shape drifted")
    fields = lines[-1].split("\t")
    body = raw[: -(len(lines[-1]) + 1)]
    if (
        len(fields) != 2
        or not HASH_RE.fullmatch(fields[1])
        or _sha256(domain + body) != fields[1]
    ):
        raise PairedThresholdError(f"{path.name} seal drifted")
    return lines[1:-1], fields[1]


def parse_contract(path: Path) -> Contract:
    rows, seal = _sealed(path, CONTRACT_MAGIC, CONTRACT_DOMAIN)
    if seal != CONTRACT_SEAL:
        raise PairedThresholdError("WP8O contract identity drifted")
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
        raise PairedThresholdError("WP8O contract rows drifted")
    return Contract(seal)


def parse_authority(path: Path, contract_seal: str) -> Authority:
    rows, seal = _sealed(path, AUTHORITY_MAGIC, AUTHORITY_DOMAIN)
    prefix = [f"meta\t{key}\t{value}" for key, value in AUTHORITY_METADATA]
    prefix.extend(
        (
            "component\tpaired-threshold-contract\t"
            f"distribution/s4-performance/WP8O-PAIRED-THRESHOLD.tsv\t{contract_seal}",
            "parent\tpaired-evidence-authority\t"
            f"distribution/s4-performance/WP8N-AUTHORITY.tsv\t{WP8N_AUTHORITY_SEAL}",
        )
    )
    if rows[: len(prefix)] != prefix:
        raise PairedThresholdError("WP8O authority metadata or parent binding drifted")
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
            or fields[5] != "paired-threshold"
        ):
            raise PairedThresholdError("WP8O authority file row is malformed")
        records.append(FileRecord(int(fields[1], 8), int(fields[2]), fields[3], fields[4]))
    if tuple(record.path for record in records) != EXPECTED_FILES:
        raise PairedThresholdError("WP8O authority inventory drifted")
    return Authority(tuple(records), seal)


def _verify_files(root: Path, authority: Authority) -> None:
    for record in authority.files:
        path = root / record.path
        try:
            raw = wp8n._read_regular(path, record.path)
        except wp8n.PairedEvidenceError as error:
            raise PairedThresholdError(
                f"bound WP8O file is not regular: {record.path}"
            ) from error
        mode = stat.S_IFREG | stat.S_IMODE(path.lstat().st_mode)
        if mode != record.mode or len(raw) != record.size or _sha256(raw) != record.sha256:
            raise PairedThresholdError(f"bound WP8O file drifted: {record.path}")


def _static_report(contract: Contract, authority: Authority) -> tuple[bytes, str]:
    rows = (
        REPORT_MAGIC,
        f"contract\t{contract.seal}",
        f"authority\t{authority.seal}",
        f"paired-evidence-authority\t{WP8N_AUTHORITY_SEAL}",
        "status\tpaired-threshold-structurally-admitted",
        "mode\tstatic-no-bundle-no-host-no-clock-no-execution",
        "bundle-status\texternal-eligible-paired-bundle-required",
        "threshold-status\tlaw-admitted-result-unavailable",
        "claim-status\tnot-admitted",
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(REPORT_DOMAIN + body)
    return body + f"report-root\t{root}\n".encode(), root


def validate(root: Path) -> Admission:
    root = root.resolve(strict=True)
    evidence = wp8n.validate(root)
    if evidence.authority.seal != WP8N_AUTHORITY_SEAL:
        raise PairedThresholdError("WP8N parent authority drifted")
    contract = parse_contract(
        root / "distribution/s4-performance/WP8O-PAIRED-THRESHOLD.tsv"
    )
    authority = parse_authority(
        root / "distribution/s4-performance/WP8O-AUTHORITY.tsv", contract.seal
    )
    _verify_files(root, authority)
    report, report_root = _static_report(contract, authority)
    return Admission(contract, authority, evidence, report, report_root)


def _fraction(numerator: int, denominator: int) -> tuple[int, int]:
    if denominator <= 0:
        raise PairedThresholdError("fraction denominator is not positive")
    divisor = math.gcd(abs(numerator), denominator)
    return numerator // divisor, denominator // divisor


def _sign_tail(wins: int, losses: int) -> tuple[int, int]:
    if wins < 0 or losses < 0:
        raise PairedThresholdError("paired direction counts are negative")
    effective = wins + losses
    numerator = sum(math.comb(effective, count) for count in range(wins, effective + 1))
    return _fraction(numerator, 1 << effective)


def decide_kernel(comparison: wp8n.KernelComparison) -> KernelDecision:
    if (
        comparison.sample_pairs != 30
        or comparison.candidate_wins + comparison.ties + comparison.candidate_losses
        != comparison.sample_pairs
        or comparison.total_ratio_num <= 0
        or comparison.total_ratio_den <= 0
        or comparison.delta_median_den <= 0
    ):
        raise PairedThresholdError("paired comparison shape drifted")
    effective = comparison.candidate_wins + comparison.candidate_losses
    sign_num, sign_den = _sign_tail(
        comparison.candidate_wins, comparison.candidate_losses
    )
    coverage = effective >= MIN_EFFECTIVE_PAIRS
    direction = comparison.delta_median_num < 0
    sign = SIGN_ALPHA_DEN * sign_num <= SIGN_ALPHA_NUM * sign_den
    magnitude = (
        MIN_SPEEDUP_DEN * comparison.total_ratio_num
        >= MIN_SPEEDUP_NUM * comparison.total_ratio_den
    )
    passed = coverage and direction and sign and magnitude
    return KernelDecision(
        comparison.ordinal,
        comparison.name,
        comparison.sample_pairs,
        effective,
        comparison.candidate_wins,
        comparison.ties,
        comparison.candidate_losses,
        sign_num,
        sign_den,
        comparison.total_ratio_num,
        comparison.total_ratio_den,
        comparison.delta_median_num,
        comparison.delta_median_den,
        coverage,
        direction,
        sign,
        magnitude,
        passed,
    )


def _candidate_report(
    admission: Admission, replay: wp8n.Replay
) -> tuple[tuple[KernelDecision, ...], bytes, str, bool]:
    decisions = tuple(decide_kernel(item) for item in replay.session.comparisons)
    if tuple((item.ordinal, item.name) for item in decisions) != tuple(
        (ordinal, name) for ordinal, name, _oracle in wp8n.wp8m.KERNELS
    ):
        raise PairedThresholdError("paired comparison kernel inventory drifted")
    threshold_pass = len(decisions) == len(wp8n.wp8m.KERNELS) and all(
        item.kernel_pass for item in decisions
    )
    rows = [
        CANDIDATE_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"paired-evidence-authority\t{WP8N_AUTHORITY_SEAL}",
        f"bundle-root\t{replay.manifest.root}",
        f"evidence-root\t{replay.evidence_root}",
        f"session-root\t{replay.session.root}",
        f"host-attestation\t{replay.manifest.host_attestation}",
        f"source-commit\t{replay.manifest.source_commit}",
    ]
    rows.extend(
        f"kernel\t{item.ordinal}\t{item.name}\t{item.sample_pairs}\t"
        f"{item.effective_pairs}\t{item.wins}\t{item.ties}\t{item.losses}\t"
        f"{item.sign_tail_num}\t{item.sign_tail_den}\t"
        f"{item.total_ratio_num}\t{item.total_ratio_den}\t"
        f"{item.delta_median_num}\t{item.delta_median_den}\t"
        f"{'pass' if item.coverage_pass else 'fail'}\t"
        f"{'pass' if item.direction_pass else 'fail'}\t"
        f"{'pass' if item.sign_pass else 'fail'}\t"
        f"{'pass' if item.magnitude_pass else 'fail'}\t"
        f"{'pass' if item.kernel_pass else 'fail'}"
        for item in decisions
    )
    rows.extend(
        (
            f"passing-kernels\t{sum(item.kernel_pass for item in decisions)}",
            f"required-kernels\t{len(wp8n.wp8m.KERNELS)}",
            f"threshold-candidate\t{'pass' if threshold_pass else 'fail'}",
            "claim-status\tnot-admitted",
            "claim-authority\trequired-not-admitted",
        )
    )
    body = b"".join(f"{row}\n".encode() for row in rows)
    root = _sha256(CANDIDATE_DOMAIN + body)
    return decisions, body + f"candidate-root\t{root}\n".encode(), root, threshold_pass


def evaluate_bundle(path: Path, admission: Admission) -> Evaluation:
    replay = wp8n.replay_bundle(path, admission.evidence)
    decisions, report, root, threshold_pass = _candidate_report(admission, replay)
    return Evaluation(replay, decisions, report, root, threshold_pass)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--bundle", type=Path)
    arguments = parser.parse_args(argv)
    try:
        admission = validate(arguments.root)
        if arguments.bundle is None:
            sys.stdout.buffer.write(admission.static_report)
        else:
            sys.stdout.buffer.write(evaluate_bundle(arguments.bundle, admission).report)
        return 0
    except (
        PairedThresholdError,
        wp8n.PairedEvidenceError,
        wp8n.wp8m.PairedRunnerError,
        wp8n.wp8m.wp8k.CandidateRunnerError,
        wp8n.wp8m.wp7c.RunnerError,
        OSError,
        ValueError,
    ) as error:
        print(f"S4-WP8O validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
