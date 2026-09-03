#!/usr/bin/env python3
"""Bind the sealed WP8M static same-session paired runner into Rocq.

The translator is intentionally untrusted. It authenticates the exact WP8M
static report and all sealed runner/carrier parents through the existing WP8M
validator, then emits a Rocq object that retains the admitted WP8K candidate
runner under the fixed same-session odd-AB/even-BA protocol. Rocq checks the
static no-host/no-clock/no-build/no-execution/no-publication/no-claim state.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_paired_runner as wp8m


class PairedRunnerCertificateError(RuntimeError):
    """The authenticated WP8M report cannot be admitted as a paired runner."""


@dataclass(frozen=True)
class PairedRunnerReport:
    report_root: str
    pairs_required: int
    invocations_required: int


def parse_authenticated_paired_runner_report(
    raw: bytes, admission: wp8m.Admission
) -> PairedRunnerReport:
    """Authenticate the exact static, non-executing WP8M report."""

    try:
        lines = wp8m._canonical(raw, "WP8M static paired-runner report")
    except wp8m.PairedRunnerError as error:
        raise PairedRunnerCertificateError(str(error)) from error
    if len(lines) != 11:
        raise PairedRunnerCertificateError(
            "WP8M static paired-runner report extent drifted"
        )
    prefix = (
        wp8m.REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"candidate-runner-authority\t{wp8m.WP8K_AUTHORITY_SEAL}",
        "runner-status\tsame-session-paired-runner-structurally-admitted",
        "acquisition-status\tretained-eligible-wp8i-host-required",
        "mode\tstatic-no-host-no-clock-no-build-no-execution",
        "sample-pairs-required\t120",
        "sample-invocations-required\t240",
        "claim-status\tnot-admitted",
    )
    if tuple(lines[: len(prefix)]) != prefix:
        raise PairedRunnerCertificateError("WP8M static paired metadata drifted")
    if raw != admission.static_report:
        raise PairedRunnerCertificateError("WP8M static paired report root drifted")
    marker = "report-root\t"
    if not lines[-1].startswith(marker):
        raise PairedRunnerCertificateError("WP8M static paired report root is missing")
    report_root = lines[-1][len(marker) :]
    if report_root != admission.report_root:
        raise PairedRunnerCertificateError("WP8M static paired report identity drifted")
    return PairedRunnerReport(report_root, 120, 240)


def emit_rocq(evidence: PairedRunnerReport, authority_seal: str) -> str:
    """Emit the closed WP8M static paired-runner certificate."""

    return "\n".join(
        [
            "(**",
            "  Generated from the sealed S4-WP8M static paired-runner report.",
            f"  WP8M authority seal: {authority_seal}",
            f"  WP8M static report root: {evidence.report_root}",
            "  The generator is untrusted. Rocq checks the imported WP8K runner,",
            "  exact two-role same-session policy, complete eleven-gate policy,",
            "  odd-AB/even-BA schedule, pair/invocation cardinality, forbidden",
            "  static actions, non-readiness, and no-performance-claim boundary.",
            "  No host, clock, build, execution, publication, measurement result,",
            "  baseline comparison, or performance claim is admitted here.",
            "*)",
            "",
            "From Stdlib Require Import List.",
            "From NauxCore Require Import ResidencyControlledHost",
            "  ResidencyMeasurementRunner ResidencyPairedRunner",
            "  GeneratedWP8KRunner.",
            "Import ListNotations.",
            "",
            "Definition wp8m_static_paired_runner :",
            "    residency_paired_measurement_runner :=",
            "  {| residency_paired_candidate_runner := wp8k_static_runner;",
            "     residency_paired_roles :=",
            "       [ResidencyPairedBaselineRole; ResidencyPairedCandidateRole];",
            "     residency_paired_baseline_retained := true;",
            "     residency_paired_gates := residency_paired_required_gates;",
            "     residency_paired_mode_value := ResidencyPairedRunnerStaticValidation;",
            "     residency_paired_host_attestation_value :=",
            "       ResidencyRunnerHostAttestationMissing;",
            "     residency_paired_explicit_entrypoint := true;",
            "     residency_paired_same_session := true;",
            "     residency_paired_same_toolchains := true;",
            "     residency_paired_schedule_value :=",
            "       ResidencyPairedScheduleOddABEvenBA;",
            f"     residency_paired_pairs_required := {evidence.pairs_required}%nat;",
            f"     residency_paired_invocations_required := {evidence.invocations_required}%nat;",
            "     residency_paired_build := ResidencyRunnerActionForbidden;",
            "     residency_paired_clock := ResidencyRunnerActionForbidden;",
            "     residency_paired_execution := ResidencyRunnerActionForbidden;",
            "     residency_paired_publication := ResidencyRunnerActionForbidden;",
            "     residency_paired_claim := ResidencyPerformanceClaimForbidden |}.",
            "",
            "Theorem wp8m_static_paired_runner_is_admitted :",
            "  residency_paired_runner_static_admitted wp8m_static_paired_runner.",
            "Proof.",
            "  constructor; simpl.",
            "  - exact wp8k_static_runner_is_admitted.",
            "  - reflexivity.",
            "  - reflexivity.",
            "  - reflexivity.",
            "  - reflexivity.",
            "  - reflexivity.",
            "  - reflexivity.",
            "  - reflexivity.",
            "  - reflexivity.",
            "  - reflexivity.",
            "  - reflexivity.",
            "  - reflexivity.",
            "  - reflexivity.",
            "  - reflexivity.",
            "  - reflexivity.",
            "  - reflexivity.",
            "  - reflexivity.",
            "Qed.",
            "",
            "Corollary wp8m_static_paired_runner_has_canonical_schedule :",
            "  residency_paired_order_for 1 = ResidencyPairAB /\\",
            "  residency_paired_order_for 2 = ResidencyPairBA.",
            "Proof. exact residency_paired_schedule_starts_ab_then_ba. Qed.",
            "",
            "Corollary wp8m_static_paired_runner_has_two_invocations_per_pair :",
            "  (2 * residency_paired_pairs_required wp8m_static_paired_runner)%nat =",
            "    residency_paired_invocations_required wp8m_static_paired_runner.",
            "Proof.",
            "  exact (residency_static_paired_runner_invocations_are_two_per_pair",
            "    wp8m_static_paired_runner wp8m_static_paired_runner_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8m_static_paired_runner_is_not_ready :",
            "  ~ residency_paired_runner_acquisition_ready wp8m_static_paired_runner.",
            "Proof.",
            "  exact (residency_static_paired_runner_is_not_acquisition_ready",
            "    wp8m_static_paired_runner wp8m_static_paired_runner_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8m_static_paired_runner_has_no_execution_authority :",
            "  residency_paired_execution wp8m_static_paired_runner =",
            "    ResidencyRunnerActionForbidden.",
            "Proof.",
            "  exact (residency_static_paired_runner_has_no_execution_authority",
            "    wp8m_static_paired_runner wp8m_static_paired_runner_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8m_static_paired_runner_has_no_performance_claim :",
            "  residency_paired_claim wp8m_static_paired_runner =",
            "    ResidencyPerformanceClaimForbidden.",
            "Proof.",
            "  exact (residency_static_paired_runner_has_no_performance_claim",
            "    wp8m_static_paired_runner wp8m_static_paired_runner_is_admitted).",
            "Qed.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paired-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    arguments = parser.parse_args()
    try:
        root = arguments.repo_root.resolve(strict=True)
        admission = wp8m.validate(root)
        evidence = parse_authenticated_paired_runner_report(
            arguments.paired_report.read_bytes(), admission
        )
        arguments.output.write_text(
            emit_rocq(evidence, admission.authority.seal),
            encoding="utf-8",
            newline="\n",
        )
    except (
        PairedRunnerCertificateError,
        wp8m.PairedRunnerError,
        wp8m.wp7c.RunnerError,
        wp8m.wp8k.CandidateRunnerError,
        wp8m.wp8k.wp8i.CandidateHostError,
        wp8m.wp8k.wp8j.CandidateTimingError,
        OSError,
        ValueError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
