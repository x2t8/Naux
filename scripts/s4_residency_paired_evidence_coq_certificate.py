#!/usr/bin/env python3
"""Bind the sealed WP8N static paired-evidence replay into Rocq.

The translator is intentionally untrusted. It authenticates the exact WP8N
static report and its sealed WP8M/WP8J/WP7B parents, then emits a Rocq object
that places the already-proved WP8M paired runner behind the complete WP8N
read-only replay policy. Rocq checks the missing-bundle state, exact inventory
and sample cardinalities, forbidden actions, and no-claim boundary.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_paired_evidence as wp8n


class PairedEvidenceCertificateError(RuntimeError):
    """The authenticated WP8N report cannot be admitted as a static replay."""


@dataclass(frozen=True)
class PairedEvidenceReport:
    report_root: str
    payload_files_required: int
    kernels_required: int
    pairs_per_kernel: int
    pairs_required: int
    invocations_required: int


def parse_authenticated_paired_evidence_report(
    raw: bytes, admission: wp8n.Admission
) -> PairedEvidenceReport:
    """Authenticate the exact static, bundle-free WP8N report."""

    try:
        lines = wp8n._canonical(raw, "WP8N static paired-evidence report")
    except wp8n.PairedEvidenceError as error:
        raise PairedEvidenceCertificateError(str(error)) from error
    if len(lines) != 9:
        raise PairedEvidenceCertificateError(
            "WP8N static paired-evidence report extent drifted"
        )
    prefix = (
        wp8n.REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"paired-runner-authority\t{wp8n.WP8M_AUTHORITY_SEAL}",
        "status\tpaired-evidence-replay-structurally-admitted",
        "mode\tstatic-no-bundle-no-host-no-clock-no-execution",
        "bundle-status\texternal-eligible-paired-bundle-required",
        "claim-status\tnot-admitted",
    )
    if tuple(lines[: len(prefix)]) != prefix:
        raise PairedEvidenceCertificateError(
            "WP8N static paired-evidence metadata drifted"
        )
    if raw != admission.static_report:
        raise PairedEvidenceCertificateError(
            "WP8N static paired-evidence report root drifted"
        )
    marker = "report-root\t"
    if not lines[-1].startswith(marker):
        raise PairedEvidenceCertificateError(
            "WP8N static paired-evidence report root is missing"
        )
    report_root = lines[-1][len(marker) :]
    if report_root != admission.report_root:
        raise PairedEvidenceCertificateError(
            "WP8N static paired-evidence report identity drifted"
        )
    return PairedEvidenceReport(report_root, 12, 4, 30, 120, 240)


def emit_rocq(evidence: PairedEvidenceReport, authority_seal: str) -> str:
    """Emit the closed WP8N static paired-evidence certificate."""

    return "\n".join(
        [
            "(**",
            "  Generated from the sealed S4-WP8N static paired-evidence report.",
            f"  WP8N authority seal: {authority_seal}",
            f"  WP8N static report root: {evidence.report_root}",
            "  The generator is untrusted. Rocq checks the imported WP8M runner,",
            "  complete eleven-gate policy, exact inventory and paired sample",
            "  cardinalities, missing bundle, forbidden static actions,",
            "  non-readiness, and no-performance-claim boundary.",
            "  No bundle, host observation, clock read, build, execution,",
            "  mutation, publication, comparison result, or claim is admitted.",
            "*)",
            "",
            "From NauxCore Require Import ResidencyControlledHost",
            "  ResidencyPairedRunner ResidencyPairedEvidenceReplay",
            "  GeneratedWP8MPairedRunner.",
            "",
            "Definition wp8n_static_paired_evidence_replay :",
            "    residency_paired_evidence_replay :=",
            "  {| residency_paired_evidence_runner := wp8m_static_paired_runner;",
            "     residency_paired_evidence_gates :=",
            "       residency_paired_evidence_required_gates;",
            "     residency_paired_evidence_mode_value :=",
            "       ResidencyPairedEvidenceStaticValidation;",
            "     residency_paired_evidence_bundle_value :=",
            "       ResidencyPairedEvidenceBundleMissing;",
            "     residency_paired_evidence_explicit_entrypoint := true;",
            f"     residency_paired_evidence_payload_files_required := {evidence.payload_files_required}%nat;",
            f"     residency_paired_evidence_kernels_required := {evidence.kernels_required}%nat;",
            f"     residency_paired_evidence_pairs_per_kernel := {evidence.pairs_per_kernel}%nat;",
            f"     residency_paired_evidence_pairs_required := {evidence.pairs_required}%nat;",
            f"     residency_paired_evidence_invocations_required := {evidence.invocations_required}%nat;",
            "     residency_paired_evidence_replay_action :=",
            "       ResidencyRunnerActionForbidden;",
            "     residency_paired_evidence_live_host := ResidencyRunnerActionForbidden;",
            "     residency_paired_evidence_clock := ResidencyRunnerActionForbidden;",
            "     residency_paired_evidence_build := ResidencyRunnerActionForbidden;",
            "     residency_paired_evidence_execution :=",
            "       ResidencyRunnerActionForbidden;",
            "     residency_paired_evidence_mutation := ResidencyRunnerActionForbidden;",
            "     residency_paired_evidence_publication :=",
            "       ResidencyRunnerActionForbidden;",
            "     residency_paired_evidence_claim :=",
            "       ResidencyPerformanceClaimForbidden |}.",
            "",
            "Theorem wp8n_static_paired_evidence_replay_is_admitted :",
            "  residency_paired_evidence_static_admitted",
            "    wp8n_static_paired_evidence_replay.",
            "Proof.",
            "  constructor; simpl.",
            "  - exact wp8m_static_paired_runner_is_admitted.",
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
            "  - reflexivity.",
            "Qed.",
            "",
            "Corollary wp8n_static_paired_evidence_has_exact_cardinality :",
            "  (residency_paired_evidence_kernels_required",
            "     wp8n_static_paired_evidence_replay *",
            "   residency_paired_evidence_pairs_per_kernel",
            "     wp8n_static_paired_evidence_replay =",
            "   residency_paired_evidence_pairs_required",
            "     wp8n_static_paired_evidence_replay)%nat /\\",
            "  (2 * residency_paired_evidence_pairs_required",
            "     wp8n_static_paired_evidence_replay =",
            "   residency_paired_evidence_invocations_required",
            "     wp8n_static_paired_evidence_replay)%nat.",
            "Proof.",
            "  exact (residency_static_paired_evidence_has_exact_cardinality",
            "    wp8n_static_paired_evidence_replay",
            "    wp8n_static_paired_evidence_replay_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8n_static_paired_evidence_has_no_bundle :",
            "  residency_paired_evidence_bundle_value",
            "    wp8n_static_paired_evidence_replay =",
            "    ResidencyPairedEvidenceBundleMissing.",
            "Proof.",
            "  exact (residency_static_paired_evidence_has_no_bundle",
            "    wp8n_static_paired_evidence_replay",
            "    wp8n_static_paired_evidence_replay_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8n_static_paired_evidence_is_not_ready :",
            "  ~ residency_paired_evidence_replay_ready",
            "      wp8n_static_paired_evidence_replay.",
            "Proof.",
            "  exact (residency_static_paired_evidence_is_not_ready",
            "    wp8n_static_paired_evidence_replay",
            "    wp8n_static_paired_evidence_replay_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8n_static_paired_evidence_has_no_replay_authority :",
            "  residency_paired_evidence_replay_action",
            "    wp8n_static_paired_evidence_replay =",
            "    ResidencyRunnerActionForbidden.",
            "Proof.",
            "  exact (residency_static_paired_evidence_has_no_replay_authority",
            "    wp8n_static_paired_evidence_replay",
            "    wp8n_static_paired_evidence_replay_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8n_static_paired_evidence_has_no_performance_claim :",
            "  residency_paired_evidence_claim wp8n_static_paired_evidence_replay =",
            "    ResidencyPerformanceClaimForbidden.",
            "Proof.",
            "  exact (residency_paired_evidence_static_claim_forbidden",
            "    wp8n_static_paired_evidence_replay",
            "    wp8n_static_paired_evidence_replay_is_admitted).",
            "Qed.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paired-evidence-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    arguments = parser.parse_args()
    try:
        root = arguments.repo_root.resolve(strict=True)
        admission = wp8n.validate(root)
        evidence = parse_authenticated_paired_evidence_report(
            arguments.paired_evidence_report.read_bytes(), admission
        )
        arguments.output.write_text(
            emit_rocq(evidence, admission.authority.seal),
            encoding="utf-8",
            newline="\n",
        )
    except (
        PairedEvidenceCertificateError,
        wp8n.PairedEvidenceError,
        wp8n.wp8m.PairedRunnerError,
        wp8n.wp8m.wp8k.CandidateRunnerError,
        wp8n.wp8m.wp8k.wp8i.CandidateHostError,
        wp8n.wp8m.wp8k.wp8j.CandidateTimingError,
        OSError,
        ValueError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
