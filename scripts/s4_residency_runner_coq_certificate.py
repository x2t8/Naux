#!/usr/bin/env python3
"""Bind the sealed WP8K static measurement runner admission into Rocq.

The translator is intentionally untrusted.  It authenticates the exact WP8K
static report and its sealed WP8I/WP8J parents, then emits a small Rocq object
that assembles the four already-proved WP8J carriers under the ten-gate WP8K
policy.  Rocq checks the static no-host/no-clock/no-build/no-execution/no-
publication state and the absence of performance-claim authority.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_measurement_runner as wp8k


class RunnerCertificateError(RuntimeError):
    """The authenticated WP8K report cannot be admitted as a static runner."""


@dataclass(frozen=True)
class RunnerReportEvidence:
    report_root: str
    samples_required: int


def parse_authenticated_runner_report(
    raw: bytes, admission: wp8k.Admission
) -> RunnerReportEvidence:
    """Authenticate the exact static, non-executing WP8K report."""

    try:
        lines = wp8k._canonical(raw, "WP8K static runner report", 131_072)
    except wp8k.CandidateRunnerError as error:
        raise RunnerCertificateError(str(error)) from error
    if len(lines) != 11:
        raise RunnerCertificateError("WP8K static runner report extent drifted")
    prefix = (
        wp8k.REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"candidate-host-authority\t{wp8k.WP8I_AUTHORITY_SEAL}",
        f"candidate-carrier-authority\t{wp8k.WP8J_AUTHORITY_SEAL}",
        "runner-status\tcandidate-measurement-runner-structurally-admitted",
        "acquisition-status\tretained-eligible-wp8i-host-required",
        "mode\tstatic-no-host-no-clock-no-build-no-execution",
        "claim-status\tnot-admitted",
        "samples-required\t120",
    )
    if tuple(lines[: len(prefix)]) != prefix:
        raise RunnerCertificateError("WP8K static runner metadata drifted")
    if raw != admission.static_report:
        raise RunnerCertificateError("WP8K static runner report root drifted")
    marker = "report-root\t"
    if not lines[-1].startswith(marker):
        raise RunnerCertificateError("WP8K static runner report root is missing")
    report_root = lines[-1][len(marker) :]
    if report_root != admission.report_root:
        raise RunnerCertificateError("WP8K static runner report identity drifted")
    return RunnerReportEvidence(report_root, 120)


def emit_rocq(evidence: RunnerReportEvidence, authority_seal: str) -> str:
    """Emit the closed WP8K structural runner certificate."""

    modules = " ".join(
        f"GeneratedWP8JTimingKernel{ordinal}" for ordinal in ("01", "02", "03", "04")
    )
    carriers = [f"wp8j_kernel_{ordinal}_carrier" for ordinal in ("01", "02", "03", "04")]
    rows = [
        "(**",
        "  Generated from the sealed S4-WP8K static runner report.",
        f"  WP8K authority seal: {authority_seal}",
        f"  WP8K static report root: {evidence.report_root}",
        "  The generator is untrusted. Rocq checks the exact four-carrier",
        "  extent, every imported WP8J carrier admission, the complete ten-",
        "  gate policy, explicit-only entrypoint, sample target, forbidden",
        "  actions, non-readiness, and no-performance-claim boundary.",
        "  No host observation, clock read, build, execution, publication,",
        "  measurement result, or performance claim is admitted here.",
        "*)",
        "",
        "From Stdlib Require Import List.",
        "From NauxCore Require Import ResidencyControlledHost",
        f"  ResidencyMeasurementRunner {modules}.",
        "Import ListNotations.",
        "",
        "Definition wp8k_static_runner_carriers : list residency_timing_carrier :=",
        "  [ " + "; ".join(carriers) + " ].",
        "",
        "Example wp8k_static_runner_carrier_extent :",
        "  length wp8k_static_runner_carriers = 4%nat.",
        "Proof. reflexivity. Qed.",
        "",
        "Theorem wp8k_static_runner_carriers_are_admitted :",
        "  Forall residency_timing_carrier_admitted",
        "    wp8k_static_runner_carriers.",
        "Proof.",
        "  unfold wp8k_static_runner_carriers.",
        "  constructor.",
        "  - exact wp8j_kernel_01_carrier_is_admitted.",
        "  - constructor.",
        "    + exact wp8j_kernel_02_carrier_is_admitted.",
        "    + constructor.",
        "      * exact wp8j_kernel_03_carrier_is_admitted.",
        "      * constructor.",
        "        -- exact wp8j_kernel_04_carrier_is_admitted.",
        "        -- constructor.",
        "Qed.",
        "",
        "Definition wp8k_static_runner : residency_measurement_runner :=",
        "  {| residency_runner_carriers := wp8k_static_runner_carriers;",
        "     residency_runner_gates := residency_runner_required_gates;",
        "     residency_runner_mode_value := ResidencyRunnerStaticValidation;",
        "     residency_runner_host_attestation_value :=",
        "       ResidencyRunnerHostAttestationMissing;",
        "     residency_runner_explicit_entrypoint := true;",
        f"     residency_runner_samples_required := {evidence.samples_required}%nat;",
        "     residency_runner_clock := ResidencyRunnerActionForbidden;",
        "     residency_runner_build := ResidencyRunnerActionForbidden;",
        "     residency_runner_execution := ResidencyRunnerActionForbidden;",
        "     residency_runner_publication := ResidencyRunnerActionForbidden;",
        "     residency_runner_claim := ResidencyPerformanceClaimForbidden |}.",
        "",
        "Theorem wp8k_static_runner_is_admitted :",
        "  residency_measurement_runner_static_admitted wp8k_static_runner.",
        "Proof.",
        "  unfold residency_measurement_runner_static_admitted,",
        "    wp8k_static_runner.",
        "  split; [exact wp8k_static_runner_carrier_extent |].",
        "  split; [exact wp8k_static_runner_carriers_are_admitted |].",
        "  split; [reflexivity |].",
        "  split; [reflexivity |].",
        "  split; [reflexivity |].",
        "  split; [reflexivity |].",
        "  split; [reflexivity |].",
        "  split; [reflexivity |].",
        "  split; [reflexivity |].",
        "  split; [reflexivity |].",
        "  split; reflexivity.",
        "Qed.",
        "",
        "Corollary wp8k_static_runner_is_not_acquisition_ready :",
        "  ~ residency_measurement_runner_acquisition_ready wp8k_static_runner.",
        "Proof.",
        "  exact (residency_static_runner_is_not_acquisition_ready",
        "    wp8k_static_runner wp8k_static_runner_is_admitted).",
        "Qed.",
        "",
        "Corollary wp8k_static_runner_has_no_execution_authority :",
        "  residency_runner_execution wp8k_static_runner =",
        "    ResidencyRunnerActionForbidden.",
        "Proof.",
        "  exact (residency_static_runner_has_no_execution_authority",
        "    wp8k_static_runner wp8k_static_runner_is_admitted).",
        "Qed.",
        "",
        "Corollary wp8k_static_runner_has_no_publication_authority :",
        "  residency_runner_publication wp8k_static_runner =",
        "    ResidencyRunnerActionForbidden.",
        "Proof.",
        "  exact (residency_static_runner_has_no_publication_authority",
        "    wp8k_static_runner wp8k_static_runner_is_admitted).",
        "Qed.",
        "",
        "Corollary wp8k_static_runner_has_no_performance_claim :",
        "  residency_runner_claim wp8k_static_runner =",
        "    ResidencyPerformanceClaimForbidden.",
        "Proof.",
        "  exact (residency_static_runner_has_no_performance_claim",
        "    wp8k_static_runner wp8k_static_runner_is_admitted).",
        "Qed.",
        "",
        "Corollary wp8k_static_runner_carriers_are_not_runnable :",
        "  Forall (fun carrier => ~ residency_timing_carrier_runnable carrier)",
        "    wp8k_static_runner_carriers.",
        "Proof.",
        "  exact (residency_static_runner_carriers_remain_non_runnable",
        "    wp8k_static_runner wp8k_static_runner_is_admitted).",
        "Qed.",
        "",
    ]
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    arguments = parser.parse_args()
    try:
        root = arguments.repo_root.resolve(strict=True)
        admission = wp8k.validate(root)
        evidence = parse_authenticated_runner_report(
            arguments.runner_report.read_bytes(), admission
        )
        output = emit_rocq(evidence, admission.authority.seal)
        arguments.output.write_text(output, encoding="utf-8", newline="\n")
    except (
        RunnerCertificateError,
        wp8k.CandidateRunnerError,
        wp8k.wp7c.RunnerError,
        wp8k.wp8i.CandidateHostError,
        wp8k.wp8j.CandidateTimingError,
        OSError,
        ValueError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
