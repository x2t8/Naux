#!/usr/bin/env python3
"""Bind the sealed, blocked WP8P claim protocol into Rocq."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_claim_admission as wp8p


class ClaimAdmissionCertificateError(RuntimeError):
    """The authenticated WP8P report cannot be admitted as blocked."""


@dataclass(frozen=True)
class ClaimAdmissionReport:
    report_root: str
    blocker_count: int


def parse_authenticated_claim_admission_report(
    raw: bytes, admission: wp8p.Admission
) -> ClaimAdmissionReport:
    """Authenticate the exact static WP8P refusal report."""

    try:
        lines = wp8p.wp8o.wp8n._canonical(raw, "WP8P static claim report")
    except wp8p.wp8o.wp8n.PairedEvidenceError as error:
        raise ClaimAdmissionCertificateError(str(error)) from error
    if len(lines) != 10:
        raise ClaimAdmissionCertificateError("WP8P static report extent drifted")
    prefix = (
        wp8p.REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"parent-paired-threshold-authority\t{wp8p.WP8O_AUTHORITY_SEAL}",
        "protocol-status\tregister-residency-claim-protocol-structurally-admitted",
        "admission-status\tblocked",
        "mode\tstatic-no-host-no-network-no-clock-no-execution",
        "claim-status\tnot-admitted",
        f"blockers\t{len(wp8p.BLOCKERS)}",
    )
    if tuple(lines[: len(prefix)]) != prefix:
        raise ClaimAdmissionCertificateError("WP8P static metadata drifted")
    if raw != admission.report:
        raise ClaimAdmissionCertificateError("WP8P static report root drifted")
    marker = "report-root\t"
    if not lines[-1].startswith(marker):
        raise ClaimAdmissionCertificateError("WP8P report root is missing")
    root = lines[-1][len(marker) :]
    if root != admission.report_root:
        raise ClaimAdmissionCertificateError("WP8P report identity drifted")
    return ClaimAdmissionReport(root, len(wp8p.BLOCKERS))


def emit_rocq(report: ClaimAdmissionReport, authority_seal: str) -> str:
    """Emit a closed WP8P protocol object with all blockers retained."""

    return "\n".join(
        [
            "(**",
            "  Generated from the sealed S4-WP8P static claim report.",
            f"  WP8P authority seal: {authority_seal}",
            f"  WP8P static report root: {report.report_root}",
            f"  Retained blockers: {report.blocker_count}",
            "  The generator is untrusted. Rocq checks the imported WP8O law,",
            "  eight gates, four claim classes, four unresolved blockers, absent",
            "  request and approval, forbidden actions, and no-claim boundary.",
            "*)",
            "",
            "From NauxCore Require Import ResidencyControlledHost",
            "  ResidencyMeasurementRunner ResidencyPairedThreshold",
            "  ResidencyClaimAdmission GeneratedWP8OThreshold.",
            "",
            "Definition wp8p_static_claim_protocol : residency_claim_protocol :=",
            "  {| residency_claim_parent := wp8o_static_paired_threshold_evaluator;",
            "     residency_claim_gates := residency_claim_required_gates;",
            "     residency_claim_classes_value := residency_claim_classes;",
            "     residency_claim_unresolved_blockers :=",
            "       residency_claim_required_blockers;",
            "     residency_claim_mode_value := ResidencyClaimProtocolStaticBlocked;",
            "     residency_claim_request_value := ResidencyClaimRequestMissing;",
            "     residency_claim_approval_value := ResidencyClaimApprovalMissing;",
            "     residency_claim_explicit_entrypoint := false;",
            "     residency_claim_host := ResidencyRunnerActionForbidden;",
            "     residency_claim_network := ResidencyRunnerActionForbidden;",
            "     residency_claim_clock := ResidencyRunnerActionForbidden;",
            "     residency_claim_build := ResidencyRunnerActionForbidden;",
            "     residency_claim_execution := ResidencyRunnerActionForbidden;",
            "     residency_claim_admission := ResidencyRunnerActionForbidden;",
            "     residency_claim_authority := ResidencyPerformanceClaimForbidden |}.",
            "",
            "Theorem wp8p_static_claim_protocol_is_admitted :",
            "  residency_claim_protocol_static_admitted wp8p_static_claim_protocol.",
            "Proof.",
            "  constructor; simpl; try reflexivity.",
            "  exact wp8o_static_paired_threshold_is_admitted.",
            "Qed.",
            "",
            "Corollary wp8p_static_claim_protocol_has_four_blockers :",
            "  length (residency_claim_unresolved_blockers",
            "    wp8p_static_claim_protocol) = 4%nat.",
            "Proof.",
            "  exact (residency_static_claim_protocol_has_four_blockers",
            "    wp8p_static_claim_protocol wp8p_static_claim_protocol_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8p_static_claim_protocol_is_not_resolved :",
            "  ~ residency_claim_protocol_blockers_resolved",
            "      wp8p_static_claim_protocol.",
            "Proof.",
            "  exact (residency_static_claim_protocol_is_not_resolved",
            "    wp8p_static_claim_protocol wp8p_static_claim_protocol_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8p_static_claim_protocol_has_no_request_or_approval :",
            "  residency_claim_request_value wp8p_static_claim_protocol =",
            "    ResidencyClaimRequestMissing /\\",
            "  residency_claim_approval_value wp8p_static_claim_protocol =",
            "    ResidencyClaimApprovalMissing.",
            "Proof.",
            "  exact (residency_static_claim_protocol_has_no_request_or_approval",
            "    wp8p_static_claim_protocol wp8p_static_claim_protocol_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8p_static_claim_protocol_has_no_admission_authority :",
            "  residency_claim_admission wp8p_static_claim_protocol =",
            "    ResidencyRunnerActionForbidden /\\",
            "  residency_claim_authority wp8p_static_claim_protocol =",
            "    ResidencyPerformanceClaimForbidden.",
            "Proof.",
            "  exact (residency_static_claim_protocol_has_no_admission_authority",
            "    wp8p_static_claim_protocol wp8p_static_claim_protocol_is_admitted).",
            "Qed.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    arguments = parser.parse_args()
    try:
        root = arguments.repo_root.resolve(strict=True)
        admission = wp8p.validate(root)
        report = parse_authenticated_claim_admission_report(
            arguments.claim_report.read_bytes(), admission
        )
        arguments.output.write_text(
            emit_rocq(report, admission.authority.seal),
            encoding="utf-8",
            newline="\n",
        )
    except (
        ClaimAdmissionCertificateError,
        wp8p.ClaimAdmissionError,
        wp8p.wp8o.PairedThresholdError,
        wp8p.wp8o.wp8n.PairedEvidenceError,
        OSError,
        ValueError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
