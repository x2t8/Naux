#!/usr/bin/env python3
"""Bind the sealed WP8Q public-protocol receipt into Rocq."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_public_protocol as wp8q


class PublicProtocolCertificateError(RuntimeError):
    """The authenticated WP8Q report cannot be admitted."""


@dataclass(frozen=True)
class PublicProtocolReport:
    report_root: str
    tracked_commit: str
    ci_run: str
    formal_model_run: str
    formal_bridge_run: str
    blocker_count: int


def parse_authenticated_public_protocol_report(
    raw: bytes, admission: wp8q.Admission
) -> PublicProtocolReport:
    """Authenticate the exact static WP8Q report."""

    try:
        lines = wp8q.wp8p.wp8o.wp8n._canonical(raw, "WP8Q static public report")
    except wp8q.wp8p.wp8o.wp8n.PairedEvidenceError as error:
        raise PublicProtocolCertificateError(str(error)) from error
    if len(lines) != 14:
        raise PublicProtocolCertificateError("WP8Q static report extent drifted")
    prefix = (
        wp8q.REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"parent-claim-admission-authority\t{wp8q.WP8P_AUTHORITY_SEAL}",
        f"tracked-commit\t{wp8q.TRACKED_COMMIT}",
        f"ci-run\t{wp8q.RUNS[0][2]}",
        f"formal-model-run\t{wp8q.RUNS[1][2]}",
        f"formal-residency-bridge-run\t{wp8q.RUNS[2][2]}",
        "public-protocol-gate\tclosed",
        "observation-mode\treviewed-static-public-record-no-network",
        "admission-status\tblocked",
        "claim-status\tnot-admitted",
        f"blockers\t{len(wp8q.BLOCKERS)}",
    )
    if tuple(lines[: len(prefix)]) != prefix:
        raise PublicProtocolCertificateError("WP8Q static metadata drifted")
    if raw != admission.report:
        raise PublicProtocolCertificateError("WP8Q static report root drifted")
    marker = "report-root\t"
    if not lines[-1].startswith(marker):
        raise PublicProtocolCertificateError("WP8Q report root is missing")
    root = lines[-1][len(marker) :]
    if root != admission.report_root:
        raise PublicProtocolCertificateError("WP8Q report identity drifted")
    return PublicProtocolReport(
        root,
        wp8q.TRACKED_COMMIT,
        wp8q.RUNS[0][2],
        wp8q.RUNS[1][2],
        wp8q.RUNS[2][2],
        len(wp8q.BLOCKERS),
    )


def _nat_list(raw: bytes) -> str:
    return "[" + "; ".join(str(value) for value in raw) + "]"


def emit_rocq(report: PublicProtocolReport, authority_seal: str) -> str:
    """Emit the closed WP8Q receipt while preserving every claim refusal."""

    commit_bytes = bytes.fromhex(report.tracked_commit)
    return "\n".join(
        [
            "(**",
            "  Generated from the sealed S4-WP8Q public-protocol receipt.",
            f"  WP8Q authority seal: {authority_seal}",
            f"  WP8Q static report root: {report.report_root}",
            f"  Tracked commit: {report.tracked_commit}",
            f"  Remaining blockers: {report.blocker_count}",
            "  The generator is untrusted. Rocq checks the imported WP8P law,",
            "  exact commit width, nonempty public run identities, closed public",
            "  gate, retained blockers, absent request/approval, and no claim.",
            "*)",
            "",
            "From Stdlib Require Import List.",
            "Import ListNotations.",
            "From NauxCore Require Import ResidencyControlledHost",
            "  ResidencyMeasurementRunner ResidencyClaimAdmission",
            "  ResidencyPublicProtocolAcceptance GeneratedWP8PClaimAdmission.",
            "",
            "Definition wp8q_tracked_commit : list nat :=",
            f"  {_nat_list(commit_bytes)}.",
            "",
            "Definition wp8q_ci_run_identity : list nat :=",
            f"  {_nat_list(report.ci_run.encode('ascii'))}.",
            "",
            "Definition wp8q_formal_model_run_identity : list nat :=",
            f"  {_nat_list(report.formal_model_run.encode('ascii'))}.",
            "",
            "Definition wp8q_formal_bridge_run_identity : list nat :=",
            f"  {_nat_list(report.formal_bridge_run.encode('ascii'))}.",
            "",
            "Definition wp8q_public_protocol_receipt :",
            "    residency_public_protocol_receipt :=",
            "  {| residency_public_protocol_parent := wp8p_static_claim_protocol;",
            "     residency_public_protocol_commit := wp8q_tracked_commit;",
            "     residency_public_protocol_ci_run := wp8q_ci_run_identity;",
            "     residency_public_protocol_formal_model_run :=",
            "       wp8q_formal_model_run_identity;",
            "     residency_public_protocol_formal_bridge_run :=",
            "       wp8q_formal_bridge_run_identity;",
            "     residency_public_protocol_ci_commit := wp8q_tracked_commit;",
            "     residency_public_protocol_formal_model_commit :=",
            "       wp8q_tracked_commit;",
            "     residency_public_protocol_formal_bridge_commit :=",
            "       wp8q_tracked_commit;",
            "     residency_public_protocol_ci_success := true;",
            "     residency_public_protocol_formal_model_success := true;",
            "     residency_public_protocol_formal_bridge_success := true;",
            "     residency_public_protocol_public_records := true;",
            "     residency_public_protocol_mode_value :=",
            "       ResidencyPublicProtocolStaticReviewed;",
            "     residency_public_protocol_unresolved_blockers :=",
            "       residency_public_protocol_remaining_blockers;",
            "     residency_public_protocol_request := ResidencyClaimRequestMissing;",
            "     residency_public_protocol_approval := ResidencyClaimApprovalMissing;",
            "     residency_public_protocol_network := ResidencyRunnerActionForbidden;",
            "     residency_public_protocol_clock := ResidencyRunnerActionForbidden;",
            "     residency_public_protocol_build := ResidencyRunnerActionForbidden;",
            "     residency_public_protocol_execution := ResidencyRunnerActionForbidden;",
            "     residency_public_protocol_admission := ResidencyRunnerActionForbidden;",
            "     residency_public_protocol_claim_authority :=",
            "       ResidencyPerformanceClaimForbidden |}.",
            "",
            "Theorem wp8q_public_protocol_receipt_is_admitted :",
            "  residency_public_protocol_receipt_admitted",
            "    wp8q_public_protocol_receipt.",
            "Proof.",
            "  constructor.",
            "  - exact wp8p_static_claim_protocol_is_admitted.",
            "  - reflexivity.",
            "  - discriminate.",
            "  - discriminate.",
            "  - discriminate.",
            "  all: reflexivity.",
            "Qed.",
            "",
            "Corollary wp8q_public_protocol_gate_is_closed :",
            "  residency_public_protocol_gate_closed wp8q_public_protocol_receipt.",
            "Proof.",
            "  exact (residency_public_protocol_admission_closes_public_gate",
            "    wp8q_public_protocol_receipt",
            "    wp8q_public_protocol_receipt_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8q_public_protocol_retains_three_blockers :",
            "  length (residency_public_protocol_unresolved_blockers",
            "    wp8q_public_protocol_receipt) = 3%nat.",
            "Proof.",
            "  exact (residency_public_protocol_admission_retains_three_blockers",
            "    wp8q_public_protocol_receipt",
            "    wp8q_public_protocol_receipt_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8q_public_protocol_removes_only_public_blocker :",
            "  ~ In ResidencyClaimBlockerPublicProtocol",
            "      (residency_public_protocol_unresolved_blockers",
            "        wp8q_public_protocol_receipt) /\\",
            "  In ResidencyClaimBlockerEligibleBundle",
            "    (residency_public_protocol_unresolved_blockers",
            "      wp8q_public_protocol_receipt) /\\",
            "  In ResidencyClaimBlockerExactRequest",
            "    (residency_public_protocol_unresolved_blockers",
            "      wp8q_public_protocol_receipt) /\\",
            "  In ResidencyClaimBlockerDistinctApproval",
            "    (residency_public_protocol_unresolved_blockers",
            "      wp8q_public_protocol_receipt).",
            "Proof.",
            "  exact (residency_public_protocol_admission_removes_only_public_blocker",
            "    wp8q_public_protocol_receipt",
            "    wp8q_public_protocol_receipt_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8q_public_protocol_has_no_claim_path :",
            "  ~ residency_public_protocol_claim_ready wp8q_public_protocol_receipt.",
            "Proof.",
            "  exact (residency_public_protocol_admission_has_no_claim_path",
            "    wp8q_public_protocol_receipt",
            "    wp8q_public_protocol_receipt_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8q_public_protocol_has_no_claim_authority :",
            "  residency_public_protocol_admission wp8q_public_protocol_receipt =",
            "    ResidencyRunnerActionForbidden /\\",
            "  residency_public_protocol_claim_authority wp8q_public_protocol_receipt =",
            "    ResidencyPerformanceClaimForbidden.",
            "Proof.",
            "  exact (residency_public_protocol_admission_preserves_no_claim_authority",
            "    wp8q_public_protocol_receipt",
            "    wp8q_public_protocol_receipt_is_admitted).",
            "Qed.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    arguments = parser.parse_args()
    try:
        root = arguments.repo_root.resolve(strict=True)
        admission = wp8q.validate(root)
        report = parse_authenticated_public_protocol_report(
            arguments.public_report.read_bytes(), admission
        )
        arguments.output.write_text(
            emit_rocq(report, admission.authority.seal),
            encoding="utf-8",
            newline="\n",
        )
    except (
        PublicProtocolCertificateError,
        wp8q.PublicProtocolError,
        wp8q.wp8p.ClaimAdmissionError,
        wp8q.wp8p.wp8o.PairedThresholdError,
        wp8q.wp8p.wp8o.wp8n.PairedEvidenceError,
        wp8q.wp8p.wp8o.wp8n.wp8m.PairedRunnerError,
        OSError,
        ValueError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
