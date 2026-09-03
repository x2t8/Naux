#!/usr/bin/env python3
"""Bind the sealed WP8O static paired-threshold law into Rocq.

The translator is intentionally untrusted. It authenticates the exact WP8O
static report and its sealed WP8N parent, then emits a Rocq object containing
the frozen threshold constants and the already-proved WP8N replay boundary.
Rocq checks that the static object has no candidate or evaluation authority
and cannot grant a performance claim.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_paired_threshold as wp8o


class PairedThresholdCertificateError(RuntimeError):
    """The authenticated WP8O report cannot be admitted as a static law."""


@dataclass(frozen=True)
class PairedThresholdReport:
    report_root: str
    sample_pairs_required: int
    effective_pairs_required: int
    sign_alpha_num: int
    sign_alpha_den: int
    speedup_num: int
    speedup_den: int
    kernels_required: int


def parse_authenticated_paired_threshold_report(
    raw: bytes, admission: wp8o.Admission
) -> PairedThresholdReport:
    """Authenticate the exact static, result-free WP8O report."""

    try:
        lines = wp8o.wp8n._canonical(raw, "WP8O static paired-threshold report")
    except wp8o.wp8n.PairedEvidenceError as error:
        raise PairedThresholdCertificateError(str(error)) from error
    if len(lines) != 10:
        raise PairedThresholdCertificateError(
            "WP8O static paired-threshold report extent drifted"
        )
    prefix = (
        wp8o.REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"paired-evidence-authority\t{wp8o.WP8N_AUTHORITY_SEAL}",
        "status\tpaired-threshold-structurally-admitted",
        "mode\tstatic-no-bundle-no-host-no-clock-no-execution",
        "bundle-status\texternal-eligible-paired-bundle-required",
        "threshold-status\tlaw-admitted-result-unavailable",
        "claim-status\tnot-admitted",
    )
    if tuple(lines[: len(prefix)]) != prefix:
        raise PairedThresholdCertificateError(
            "WP8O static paired-threshold metadata drifted"
        )
    if raw != admission.static_report:
        raise PairedThresholdCertificateError(
            "WP8O static paired-threshold report root drifted"
        )
    marker = "report-root\t"
    if not lines[-1].startswith(marker):
        raise PairedThresholdCertificateError(
            "WP8O static paired-threshold report root is missing"
        )
    report_root = lines[-1][len(marker) :]
    if report_root != admission.report_root:
        raise PairedThresholdCertificateError(
            "WP8O static paired-threshold report identity drifted"
        )
    return PairedThresholdReport(
        report_root=report_root,
        sample_pairs_required=30,
        effective_pairs_required=wp8o.MIN_EFFECTIVE_PAIRS,
        sign_alpha_num=wp8o.SIGN_ALPHA_NUM,
        sign_alpha_den=wp8o.SIGN_ALPHA_DEN,
        speedup_num=wp8o.MIN_SPEEDUP_NUM,
        speedup_den=wp8o.MIN_SPEEDUP_DEN,
        kernels_required=4,
    )


def emit_rocq(report: PairedThresholdReport, authority_seal: str) -> str:
    """Emit the closed WP8O static paired-threshold certificate."""

    return "\n".join(
        [
            "(**",
            "  Generated from the sealed S4-WP8O static paired-threshold report.",
            f"  WP8O authority seal: {authority_seal}",
            f"  WP8O static report root: {report.report_root}",
            "  The generator is untrusted. Rocq checks the imported WP8N replay,",
            "  complete eight-gate policy, frozen 30/24, 1/100, 21/20 and",
            "  four-kernel law, missing candidate, forbidden static actions,",
            "  non-readiness, and no-performance-claim boundary.",
            "  No bundle, kernel result, evaluation permission, host observation,",
            "  clock read, build, execution, mutation, publication, or claim is",
            "  admitted.",
            "*)",
            "",
            "From NauxCore Require Import ResidencyControlledHost",
            "  ResidencyMeasurementRunner ResidencyPairedEvidenceReplay",
            "  ResidencyPairedThreshold GeneratedWP8NPairedEvidence.",
            "",
            "Definition wp8o_static_paired_threshold_evaluator :",
            "    residency_paired_threshold_evaluator :=",
            "  {| residency_threshold_parent :=",
            "       wp8n_static_paired_evidence_replay;",
            "     residency_threshold_gates :=",
            "       residency_paired_threshold_required_gates;",
            "     residency_threshold_mode_value :=",
            "       ResidencyPairedThresholdStaticValidation;",
            "     residency_threshold_candidate_value :=",
            "       ResidencyPairedThresholdCandidateMissing;",
            "     residency_threshold_explicit_entrypoint := true;",
            f"     residency_threshold_sample_pairs_required := {report.sample_pairs_required}%nat;",
            f"     residency_threshold_effective_pairs_required := {report.effective_pairs_required}%nat;",
            f"     residency_threshold_sign_alpha_num := {report.sign_alpha_num}%nat;",
            f"     residency_threshold_sign_alpha_den := {report.sign_alpha_den}%nat;",
            f"     residency_threshold_speedup_num := {report.speedup_num}%nat;",
            f"     residency_threshold_speedup_den := {report.speedup_den}%nat;",
            f"     residency_threshold_kernels_required := {report.kernels_required}%nat;",
            "     residency_threshold_evaluation := ResidencyRunnerActionForbidden;",
            "     residency_threshold_live_host := ResidencyRunnerActionForbidden;",
            "     residency_threshold_clock := ResidencyRunnerActionForbidden;",
            "     residency_threshold_build := ResidencyRunnerActionForbidden;",
            "     residency_threshold_execution := ResidencyRunnerActionForbidden;",
            "     residency_threshold_mutation := ResidencyRunnerActionForbidden;",
            "     residency_threshold_publication := ResidencyRunnerActionForbidden;",
            "     residency_threshold_claim := ResidencyPerformanceClaimForbidden |}.",
            "",
            "Theorem wp8o_static_paired_threshold_is_admitted :",
            "  residency_paired_threshold_static_admitted",
            "    wp8o_static_paired_threshold_evaluator.",
            "Proof.",
            "  constructor; simpl; try reflexivity.",
            "  exact wp8n_static_paired_evidence_replay_is_admitted.",
            "Qed.",
            "",
            "Corollary wp8o_static_paired_threshold_has_exact_law :",
            "  (residency_threshold_effective_pairs_required",
            "     wp8o_static_paired_threshold_evaluator <=",
            "   residency_threshold_sample_pairs_required",
            "     wp8o_static_paired_threshold_evaluator)%nat /\\",
            "  residency_threshold_sign_alpha_num",
            "    wp8o_static_paired_threshold_evaluator = 1%nat /\\",
            "  residency_threshold_sign_alpha_den",
            "    wp8o_static_paired_threshold_evaluator = 100%nat /\\",
            "  residency_threshold_speedup_num",
            "    wp8o_static_paired_threshold_evaluator = 21%nat /\\",
            "  residency_threshold_speedup_den",
            "    wp8o_static_paired_threshold_evaluator = 20%nat /\\",
            "  residency_threshold_kernels_required",
            "    wp8o_static_paired_threshold_evaluator = 4%nat.",
            "Proof.",
            "  exact (residency_static_paired_threshold_has_exact_law",
            "    wp8o_static_paired_threshold_evaluator",
            "    wp8o_static_paired_threshold_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8o_static_paired_threshold_has_no_candidate :",
            "  residency_threshold_candidate_value",
            "    wp8o_static_paired_threshold_evaluator =",
            "    ResidencyPairedThresholdCandidateMissing.",
            "Proof.",
            "  exact (residency_static_paired_threshold_has_no_candidate",
            "    wp8o_static_paired_threshold_evaluator",
            "    wp8o_static_paired_threshold_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8o_static_paired_threshold_is_not_ready :",
            "  ~ residency_paired_threshold_evaluation_ready",
            "      wp8o_static_paired_threshold_evaluator.",
            "Proof.",
            "  exact (residency_static_paired_threshold_is_not_ready",
            "    wp8o_static_paired_threshold_evaluator",
            "    wp8o_static_paired_threshold_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8o_static_paired_threshold_has_no_evaluation_authority :",
            "  residency_threshold_evaluation wp8o_static_paired_threshold_evaluator =",
            "    ResidencyRunnerActionForbidden.",
            "Proof.",
            "  exact (residency_static_paired_threshold_has_no_evaluation_authority",
            "    wp8o_static_paired_threshold_evaluator",
            "    wp8o_static_paired_threshold_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8o_static_paired_threshold_has_no_performance_claim :",
            "  residency_threshold_claim wp8o_static_paired_threshold_evaluator =",
            "    ResidencyPerformanceClaimForbidden.",
            "Proof.",
            "  exact (residency_threshold_static_claim_forbidden",
            "    wp8o_static_paired_threshold_evaluator",
            "    wp8o_static_paired_threshold_is_admitted).",
            "Qed.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paired-threshold-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    arguments = parser.parse_args()
    try:
        root = arguments.repo_root.resolve(strict=True)
        admission = wp8o.validate(root)
        report = parse_authenticated_paired_threshold_report(
            arguments.paired_threshold_report.read_bytes(), admission
        )
        arguments.output.write_text(
            emit_rocq(report, admission.authority.seal),
            encoding="utf-8",
            newline="\n",
        )
    except (
        PairedThresholdCertificateError,
        wp8o.PairedThresholdError,
        wp8o.wp8n.PairedEvidenceError,
        wp8o.wp8n.wp8m.PairedRunnerError,
        wp8o.wp8n.wp8m.wp8k.CandidateRunnerError,
        OSError,
        ValueError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
