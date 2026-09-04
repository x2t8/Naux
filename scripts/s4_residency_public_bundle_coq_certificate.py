#!/usr/bin/env python3
"""Bind the sealed WP8R static public-bundle authority into Rocq."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_public_bundle as wp8r


class PublicBundleCertificateError(RuntimeError):
    """The authenticated WP8R static report cannot be admitted."""


@dataclass(frozen=True)
class PublicBundleReport:
    report_root: str
    tracked_commit: str
    blocker_count: int


def parse_authenticated_public_bundle_report(
    raw: bytes, admission: wp8r.Admission
) -> PublicBundleReport:
    """Authenticate the exact static WP8R report."""

    try:
        lines = wp8r.wp8n._canonical(raw, "WP8R static public-bundle report")
    except wp8r.wp8n.PairedEvidenceError as error:
        raise PublicBundleCertificateError(str(error)) from error
    if len(lines) != 14:
        raise PublicBundleCertificateError("WP8R static report extent drifted")
    prefix = (
        wp8r.REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"parent-public-protocol-authority\t{wp8r.WP8Q_AUTHORITY_SEAL}",
        f"parent-paired-evidence-authority\t{wp8r.WP8N_AUTHORITY_SEAL}",
        f"tracked-commit\t{wp8r.wp8q.TRACKED_COMMIT}",
        "status\tpublic-bundle-intake-structurally-admitted",
        "mode\tstatic-no-bundle-no-archive-no-network-no-execution",
        "archive-status\tabsent",
        "public-reachability\tnot-observed",
        "admission-status\tblocked",
        "claim-status\tnot-admitted",
        f"blockers\t{len(wp8r.BLOCKERS)}",
    )
    if tuple(lines[: len(prefix)]) != prefix:
        raise PublicBundleCertificateError("WP8R static metadata drifted")
    if raw != admission.report:
        raise PublicBundleCertificateError("WP8R static report root drifted")
    marker = "report-root\t"
    if not lines[-1].startswith(marker):
        raise PublicBundleCertificateError("WP8R report root is missing")
    root = lines[-1][len(marker) :]
    if root != admission.report_root:
        raise PublicBundleCertificateError("WP8R report identity drifted")
    return PublicBundleReport(
        root,
        wp8r.wp8q.TRACKED_COMMIT,
        len(wp8r.BLOCKERS),
    )


def _nat_list(raw: bytes) -> str:
    return "[" + "; ".join(str(value) for value in raw) + "]"


def emit_rocq(report: PublicBundleReport, authority_seal: str) -> str:
    """Emit the static WP8R authority with every claim blocker retained."""

    commit_bytes = bytes.fromhex(report.tracked_commit)
    return "\n".join(
        [
            "(**",
            "  Generated from the sealed S4-WP8R static public-bundle report.",
            f"  WP8R authority seal: {authority_seal}",
            f"  WP8R static report root: {report.report_root}",
            f"  Tracked commit: {report.tracked_commit}",
            f"  Remaining blockers: {report.blocker_count}",
            "  The generator is untrusted. Rocq checks both imported parents,",
            "  exact commit identity, missing archive, unobserved reachability,",
            "  retained blockers, forbidden actions, and no claim authority.",
            "*)",
            "",
            "From Stdlib Require Import List.",
            "Import ListNotations.",
            "From NauxCore Require Import ResidencyControlledHost",
            "  ResidencyMeasurementRunner ResidencyPairedEvidenceReplay",
            "  ResidencyClaimAdmission ResidencyPublicProtocolAcceptance",
            "  ResidencyPublicBundle GeneratedWP8NPairedEvidence",
            "  GeneratedWP8QPublicProtocol.",
            "",
            "Definition wp8r_tracked_commit : list nat :=",
            f"  {_nat_list(commit_bytes)}.",
            "",
            "Definition wp8r_static_public_bundle_authority :",
            "    residency_public_bundle_authority :=",
            "  {| residency_public_bundle_protocol_parent :=",
            "       wp8q_public_protocol_receipt;",
            "     residency_public_bundle_evidence_parent :=",
            "       wp8n_static_paired_evidence_replay;",
            "     residency_public_bundle_tracked_commit := wp8r_tracked_commit;",
            "     residency_public_bundle_mode_value :=",
            "       ResidencyPublicBundleStaticValidation;",
            "     residency_public_bundle_archive_value :=",
            "       ResidencyPublicBundleArchiveMissing;",
            "     residency_public_bundle_reachability_value :=",
            "       ResidencyPublicBundleReachabilityNotObserved;",
            "     residency_public_bundle_unresolved_blockers :=",
            "       residency_public_protocol_remaining_blockers;",
            "     residency_public_bundle_package_action :=",
            "       ResidencyRunnerActionForbidden;",
            "     residency_public_bundle_intake_action :=",
            "       ResidencyRunnerActionForbidden;",
            "     residency_public_bundle_network := ResidencyRunnerActionForbidden;",
            "     residency_public_bundle_clock := ResidencyRunnerActionForbidden;",
            "     residency_public_bundle_build := ResidencyRunnerActionForbidden;",
            "     residency_public_bundle_execution :=",
            "       ResidencyRunnerActionForbidden;",
            "     residency_public_bundle_publication :=",
            "       ResidencyRunnerActionForbidden;",
            "     residency_public_bundle_admission :=",
            "       ResidencyRunnerActionForbidden;",
            "     residency_public_bundle_claim_authority :=",
            "       ResidencyPerformanceClaimForbidden |}.",
            "",
            "Theorem wp8r_static_public_bundle_authority_is_admitted :",
            "  residency_public_bundle_static_admitted",
            "    wp8r_static_public_bundle_authority.",
            "Proof.",
            "  unfold wp8r_static_public_bundle_authority.",
            "  constructor.",
            "  - exact wp8q_public_protocol_receipt_is_admitted.",
            "  - exact wp8n_static_paired_evidence_replay_is_admitted.",
            "  - reflexivity. (* tracked commit *)",
            "  - reflexivity. (* static mode *)",
            "  - reflexivity. (* no archive *)",
            "  - reflexivity. (* reachability not observed *)",
            "  - reflexivity. (* remaining blockers *)",
            "  - reflexivity. (* no package action *)",
            "  - reflexivity. (* no intake action *)",
            "  - reflexivity. (* no network *)",
            "  - reflexivity. (* no clock *)",
            "  - reflexivity. (* no build *)",
            "  - reflexivity. (* no execution *)",
            "  - reflexivity. (* no publication *)",
            "  - reflexivity. (* no admission *)",
            "  - reflexivity. (* no claim *)",
            "Qed.",
            "",
            "Corollary wp8r_static_public_bundle_has_no_archive_or_reachability :",
            "  residency_public_bundle_archive_value",
            "      wp8r_static_public_bundle_authority =",
            "    ResidencyPublicBundleArchiveMissing /\\",
            "  residency_public_bundle_reachability_value",
            "      wp8r_static_public_bundle_authority =",
            "    ResidencyPublicBundleReachabilityNotObserved.",
            "Proof.",
            "  exact (residency_static_public_bundle_has_no_archive_or_reachability",
            "    wp8r_static_public_bundle_authority",
            "    wp8r_static_public_bundle_authority_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8r_static_public_bundle_retains_three_blockers :",
            "  length (residency_public_bundle_unresolved_blockers",
            "    wp8r_static_public_bundle_authority) = 3%nat.",
            "Proof.",
            "  exact (residency_static_public_bundle_retains_three_blockers",
            "    wp8r_static_public_bundle_authority",
            "    wp8r_static_public_bundle_authority_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8r_static_public_bundle_retains_eligible_blocker :",
            "  In ResidencyClaimBlockerEligibleBundle",
            "    (residency_public_bundle_unresolved_blockers",
            "      wp8r_static_public_bundle_authority).",
            "Proof.",
            "  exact (residency_static_public_bundle_retains_eligible_bundle_blocker",
            "    wp8r_static_public_bundle_authority",
            "    wp8r_static_public_bundle_authority_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8r_static_public_bundle_has_no_claim_path :",
            "  ~ residency_public_bundle_claim_ready",
            "      wp8r_static_public_bundle_authority.",
            "Proof.",
            "  exact (residency_static_public_bundle_has_no_claim_path",
            "    wp8r_static_public_bundle_authority",
            "    wp8r_static_public_bundle_authority_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8r_static_public_bundle_has_no_package_or_intake :",
            "  residency_public_bundle_package_action",
            "      wp8r_static_public_bundle_authority =",
            "    ResidencyRunnerActionForbidden /\\",
            "  residency_public_bundle_intake_action",
            "      wp8r_static_public_bundle_authority =",
            "    ResidencyRunnerActionForbidden.",
            "Proof.",
            "  exact (residency_static_public_bundle_has_no_package_or_intake_authority",
            "    wp8r_static_public_bundle_authority",
            "    wp8r_static_public_bundle_authority_is_admitted).",
            "Qed.",
            "",
            "Corollary wp8r_static_public_bundle_has_no_claim_authority :",
            "  residency_public_bundle_admission wp8r_static_public_bundle_authority =",
            "    ResidencyRunnerActionForbidden /\\",
            "  residency_public_bundle_claim_authority",
            "      wp8r_static_public_bundle_authority =",
            "    ResidencyPerformanceClaimForbidden.",
            "Proof.",
            "  split.",
            "  - exact (residency_public_bundle_static_admission_forbidden",
            "      wp8r_static_public_bundle_authority",
            "      wp8r_static_public_bundle_authority_is_admitted).",
            "  - exact (residency_public_bundle_static_claim_forbidden",
            "      wp8r_static_public_bundle_authority",
            "      wp8r_static_public_bundle_authority_is_admitted).",
            "Qed.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-bundle-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    arguments = parser.parse_args()
    try:
        root = arguments.repo_root.resolve(strict=True)
        admission = wp8r.validate(root)
        report = parse_authenticated_public_bundle_report(
            arguments.public_bundle_report.read_bytes(), admission
        )
        arguments.output.write_text(
            emit_rocq(report, admission.authority.seal),
            encoding="utf-8",
            newline="\n",
        )
    except (
        PublicBundleCertificateError,
        wp8r.PublicBundleError,
        wp8r.wp8q.PublicProtocolError,
        wp8r.wp8q.wp8p.ClaimAdmissionError,
        wp8r.wp8n.PairedEvidenceError,
        wp8r.wp8n.wp8m.PairedRunnerError,
        OSError,
        ValueError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
