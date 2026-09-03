#!/usr/bin/env python3
"""Bind the sealed WP8L static candidate-evidence replay into Rocq.

The translator is intentionally untrusted. It authenticates the exact WP8L
static report and its sealed WP8J/WP8K parents, then emits a small Rocq object
that places the already-proved WP8K runner behind the complete ten-gate WP8L
read-only replay policy. Rocq checks that the static object has no bundle and
no replay, host, clock, build, execution, mutation, or claim authority.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_evidence as wp8l


class EvidenceCertificateError(RuntimeError):
    """The authenticated WP8L report cannot be admitted as a static replay."""


@dataclass(frozen=True)
class EvidenceReport:
    report_root: str
    payload_files_required: int
    kernels_required: int
    samples_per_kernel: int
    samples_required: int


def parse_authenticated_evidence_report(
    raw: bytes, admission: wp8l.Admission
) -> EvidenceReport:
    """Authenticate the exact static, bundle-free WP8L report."""

    try:
        lines = wp8l._canonical(raw, "WP8L static evidence report", 131_072)
    except wp8l.CandidateEvidenceError as error:
        raise EvidenceCertificateError(str(error)) from error
    if len(lines) != 10:
        raise EvidenceCertificateError("WP8L static evidence report extent drifted")
    prefix = (
        wp8l.REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"candidate-runner-authority\t{wp8l.WP8K_AUTHORITY_SEAL}",
        f"candidate-carrier-authority\t{wp8l.WP8J_AUTHORITY_SEAL}",
        "status\tcandidate-evidence-replay-structurally-admitted",
        "mode\tstatic-no-bundle-no-host-no-clock-no-execution",
        "bundle-status\texternal-eligible-bundle-required",
        "claim-status\tnot-admitted",
    )
    if tuple(lines[: len(prefix)]) != prefix:
        raise EvidenceCertificateError("WP8L static evidence metadata drifted")
    if raw != admission.static_report:
        raise EvidenceCertificateError("WP8L static evidence report root drifted")
    marker = "report-root\t"
    if not lines[-1].startswith(marker):
        raise EvidenceCertificateError("WP8L static evidence report root is missing")
    report_root = lines[-1][len(marker) :]
    if report_root != admission.report_root:
        raise EvidenceCertificateError("WP8L static evidence report identity drifted")
    return EvidenceReport(report_root, 8, 4, 30, 120)


def emit_rocq(evidence: EvidenceReport, authority_seal: str) -> str:
    """Emit the closed WP8L static evidence-replay certificate."""

    rows = [
        "(**",
        "  Generated from the sealed S4-WP8L static evidence report.",
        f"  WP8L authority seal: {authority_seal}",
        f"  WP8L static report root: {evidence.report_root}",
        "  The generator is untrusted. Rocq checks the imported WP8K runner,",
        "  complete ten-gate policy, explicit-only entrypoint, exact inventory",
        "  and sample cardinalities, missing bundle, forbidden actions,",
        "  non-readiness, and no-performance-claim boundary.",
        "  No bundle, host observation, clock read, build, execution, mutation,",
        "  benchmark comparison, measurement result, or claim is admitted here.",
        "*)",
        "",
        "From NauxCore Require Import ResidencyControlledHost",
        "  ResidencyMeasurementRunner ResidencyEvidenceReplay",
        "  GeneratedWP8KRunner.",
        "",
        "Definition wp8l_static_evidence_replay : residency_evidence_replay :=",
        "  {| residency_evidence_runner := wp8k_static_runner;",
        "     residency_evidence_gates := residency_evidence_required_gates;",
        "     residency_evidence_mode_value :=",
        "       ResidencyEvidenceReplayStaticValidation;",
        "     residency_evidence_bundle_value := ResidencyEvidenceBundleMissing;",
        "     residency_evidence_explicit_entrypoint := true;",
        f"     residency_evidence_payload_files_required := {evidence.payload_files_required}%nat;",
        f"     residency_evidence_kernels_required := {evidence.kernels_required}%nat;",
        f"     residency_evidence_samples_per_kernel := {evidence.samples_per_kernel}%nat;",
        f"     residency_evidence_samples_required := {evidence.samples_required}%nat;",
        "     residency_evidence_replay_action := ResidencyRunnerActionForbidden;",
        "     residency_evidence_live_host := ResidencyRunnerActionForbidden;",
        "     residency_evidence_clock := ResidencyRunnerActionForbidden;",
        "     residency_evidence_build := ResidencyRunnerActionForbidden;",
        "     residency_evidence_execution := ResidencyRunnerActionForbidden;",
        "     residency_evidence_mutation := ResidencyRunnerActionForbidden;",
        "     residency_evidence_claim := ResidencyPerformanceClaimForbidden |}.",
        "",
        "Theorem wp8l_static_evidence_replay_is_admitted :",
        "  residency_evidence_replay_static_admitted",
        "    wp8l_static_evidence_replay.",
        "Proof.",
        "  unfold residency_evidence_replay_static_admitted,",
        "    wp8l_static_evidence_replay.",
        "  split; [exact wp8k_static_runner_is_admitted |].",
        "  repeat split; reflexivity.",
        "Qed.",
        "",
        "Corollary wp8l_static_evidence_replay_has_no_bundle :",
        "  residency_evidence_bundle_value wp8l_static_evidence_replay =",
        "    ResidencyEvidenceBundleMissing.",
        "Proof.",
        "  exact (residency_static_evidence_replay_has_no_bundle",
        "    wp8l_static_evidence_replay",
        "    wp8l_static_evidence_replay_is_admitted).",
        "Qed.",
        "",
        "Corollary wp8l_static_evidence_replay_is_not_ready :",
        "  ~ residency_evidence_replay_ready wp8l_static_evidence_replay.",
        "Proof.",
        "  exact (residency_static_evidence_replay_is_not_ready",
        "    wp8l_static_evidence_replay",
        "    wp8l_static_evidence_replay_is_admitted).",
        "Qed.",
        "",
        "Corollary wp8l_static_evidence_replay_has_no_execution_authority :",
        "  residency_evidence_execution wp8l_static_evidence_replay =",
        "    ResidencyRunnerActionForbidden.",
        "Proof.",
        "  exact (residency_static_evidence_replay_has_no_execution_authority",
        "    wp8l_static_evidence_replay",
        "    wp8l_static_evidence_replay_is_admitted).",
        "Qed.",
        "",
        "Corollary wp8l_static_evidence_replay_has_no_mutation_authority :",
        "  residency_evidence_mutation wp8l_static_evidence_replay =",
        "    ResidencyRunnerActionForbidden.",
        "Proof.",
        "  exact (residency_static_evidence_replay_has_no_mutation_authority",
        "    wp8l_static_evidence_replay",
        "    wp8l_static_evidence_replay_is_admitted).",
        "Qed.",
        "",
        "Corollary wp8l_static_evidence_replay_has_no_performance_claim :",
        "  residency_evidence_claim wp8l_static_evidence_replay =",
        "    ResidencyPerformanceClaimForbidden.",
        "Proof.",
        "  exact (residency_static_evidence_replay_has_no_performance_claim",
        "    wp8l_static_evidence_replay",
        "    wp8l_static_evidence_replay_is_admitted).",
        "Qed.",
        "",
    ]
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    arguments = parser.parse_args()
    try:
        root = arguments.repo_root.resolve(strict=True)
        admission = wp8l.validate(root)
        evidence = parse_authenticated_evidence_report(
            arguments.evidence_report.read_bytes(), admission
        )
        output = emit_rocq(evidence, admission.authority.seal)
        arguments.output.write_text(output, encoding="utf-8", newline="\n")
    except (
        EvidenceCertificateError,
        wp8l.CandidateEvidenceError,
        wp8l.wp8k.CandidateRunnerError,
        wp8l.wp8k.wp7c.RunnerError,
        wp8l.wp8k.wp8i.CandidateHostError,
        wp8l.wp8k.wp8j.CandidateTimingError,
        OSError,
        ValueError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
