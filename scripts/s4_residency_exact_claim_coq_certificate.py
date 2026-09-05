#!/usr/bin/env python3
"""Authenticate WP8S and emit its raw paired samples for Rocq recomputation."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_exact_claim as wp8s


AUTHORITY = "319b9325cdba206037908ec3663d09f945ce3358fa91f9a25ed2e5ff791ad481"
REPORT_ROOT = "fc74bb0dbf246bb23e127079c95a777e9de1b640db910debe08378a2633ae830"
BINDING_KEYS = (
    "authority", "report-root", "source-commit", "host-attestation",
    "bundle-root", "session-root", "evidence-root", "threshold-root",
    "public-intake-root", "archive-sha256", "receipt-sha256",
    "release-body-sha256", "claim-sha256",
)


class ExactClaimCertificateError(RuntimeError):
    """No certificate may be emitted for these inputs."""


@dataclass(frozen=True)
class Sample:
    number: int
    baseline_first: bool
    baseline_ns: int
    candidate_ns: int


@dataclass(frozen=True)
class Certificate:
    bindings: tuple[tuple[str, str], ...]
    claim: bytes
    samples: tuple[tuple[Sample, ...], ...]
    decisions: tuple[wp8s.wp8o.KernelDecision, ...]


def authenticate_report(raw: bytes, exact: wp8s.ExactAdmission) -> tuple[tuple[str, str], ...]:
    # Comparing the entire canonical replay result rejects extra/duplicate rows,
    # reordering, rewording and even mutations with recomputed report hashes.
    if exact.report_root != REPORT_ROOT or raw != exact.report:
        raise ExactClaimCertificateError("WP8S exact admission report drifted")
    fields = dict(line.split("\t", 1) for line in raw.decode("ascii").splitlines()[1:])
    if fields.get("authority") != AUTHORITY:
        raise ExactClaimCertificateError("WP8S authority drifted")
    return tuple((key, fields[key]) for key in BINDING_KEYS)


def extract_samples(raw: bytes, exact: wp8s.ExactAdmission) -> tuple[tuple[Sample, ...], ...]:
    """Read only samples from the authenticated session, never warmup rows."""
    wp8n = wp8s.wp8r.wp8n
    lines = wp8n._canonical(raw, "certificate paired session")
    body = raw[: -(len(lines[-1]) + 1)]
    if (
        lines[-1] != f"session-root\t{wp8s.EXPECTED.session_root}"
        or wp8s._sha256(wp8n.SESSION_DOMAIN + body) != wp8s.EXPECTED.session_root
    ):
        raise ExactClaimCertificateError("raw session identity drifted")
    try:
        index = lines.index("sample-pairs\t120") + 1
    except ValueError as error:
        raise ExactClaimCertificateError("raw session lacks sample header") from error
    kernels = []
    for ordinal, _name, oracle in wp8n.wp8m.KERNELS:
        samples = []
        for number in range(1, 31):
            index, baseline, candidate = wp8n._parse_pair(
                lines, index, "sample", ordinal, number, oracle
            )
            samples.append(Sample(number, number % 2 == 1, baseline, candidate))
        kernels.append(tuple(samples))
    if index != len(lines) - 1:
        raise ExactClaimCertificateError("raw session sample extent drifted")
    # Cross-check extraction with the already authenticated WP8N comparison.
    for samples, comparison in zip(kernels, exact.intake.replay.session.comparisons, strict=True):
        if (
            sum(p.baseline_ns for p in samples) != comparison.baseline_total_ns
            or sum(p.candidate_ns for p in samples) != comparison.candidate_total_ns
        ):
            raise ExactClaimCertificateError("extracted sample totals differ from replay")
    return tuple(kernels)


def authenticate(root: Path, report: Path, archive: Path, receipt: Path) -> Certificate:
    static = wp8s.validate(root)
    if static.authority_seal != AUTHORITY:
        raise ExactClaimCertificateError("WP8S authority drifted")
    exact = wp8s.admit(archive, receipt, static)
    bindings = authenticate_report(wp8s._regular(report, "WP8S admission report"), exact)
    # Re-read and authenticate before inspecting the tar inventory. A file
    # swapped after intake cannot inject different measurements into Rocq.
    raw = wp8s._regular(archive, "certificate archive")
    if len(raw) != wp8s.EXPECTED.archive_bytes or wp8s._sha256(raw) != wp8s.EXPECTED.archive_sha256:
        raise ExactClaimCertificateError("archive changed after replay")
    payloads = wp8s.wp8r._archive_inventory(raw, exact.intake.receipt)
    samples = extract_samples(payloads["RAW-PAIRED-SESSION.tsv"], exact)
    return Certificate(bindings, static.claim, samples, exact.decisions)


def rocq_string(raw: bytes) -> str:
    """Encode bytes as data, never interpolate executable Rocq syntax."""
    if not raw:
        return "EmptyString"
    # Readable printable runs, with an explicit byte constructor for LF etc.
    parts = []
    printable = bytearray()
    for value in raw:
        if 32 <= value <= 126:
            printable.append(value)
        else:
            if printable:
                parts.append('"' + printable.decode("ascii").replace('"', '""') + '"')
                printable.clear()
            parts.append(f"String (ascii_of_nat {value}) EmptyString")
    if printable:
        parts.append('"' + printable.decode("ascii").replace('"', '""') + '"')
    return "(" + " ++ ".join(parts) + ")%string"


def emit_rocq(certificate: Certificate) -> str:
    if len(certificate.samples) != 4 or len(certificate.decisions) != 4:
        raise ExactClaimCertificateError("certificate requires four kernels")
    lines = [
        "(** Generated from the authenticated WP8S archive and exact report.",
        "    The generator is untrusted; Rocq recomputes the finite statistics.",
        "    Hash verification, measurement provenance and external approval",
        "    remain outside the kernel, as documented in ResidencyExactClaim. *)",
        "From Stdlib Require Import List String Ascii ZArith.",
        "From NauxCore Require Import ResidencyExactClaim.",
        "Import ListNotations.",
        "Open Scope Z_scope.",
        "",
    ]
    for ordinal, (samples, decision) in enumerate(zip(certificate.samples, certificate.decisions, strict=True), 1):
        if len(samples) != 30 or decision.ordinal != f"{ordinal:02d}":
            raise ExactClaimCertificateError("certificate coverage or order drifted")
        lines.extend([
            f"Definition wp8s_kernel_{ordinal} : residency_exact_kernel :=",
            f"  {{| exact_kernel_number := {ordinal}%nat; exact_samples := [",
        ])
        for index, sample in enumerate(samples):
            order = "true" if sample.baseline_first else "false"
            end = ";" if index < len(samples) - 1 else " ] |}."
            lines.append(
                f"    {{| exact_pair_number := {sample.number}%nat; "
                f"exact_baseline_first := {order}; "
                f"exact_baseline_ns := {sample.baseline_ns}; "
                f"exact_candidate_ns := {sample.candidate_ns} |}}{end}"
            )
        lines.extend([
            f"Definition wp8s_metrics_{ordinal} : residency_exact_metrics :=",
            f"  {{| exact_report_wins := {decision.wins}%nat;",
            f"     exact_report_ties := {decision.ties}%nat;",
            f"     exact_report_losses := {decision.losses}%nat;",
            f"     exact_report_sign_num := {decision.sign_tail_num};",
            f"     exact_report_sign_den := {decision.sign_tail_den};",
            f"     exact_report_ratio_num := {decision.total_ratio_num};",
            f"     exact_report_ratio_den := {decision.total_ratio_den};",
            f"     exact_report_median_num := {decision.delta_median_num};",
            f"     exact_report_median_den := {decision.delta_median_den} |}}.",
            f"Theorem wp8s_kernel_{ordinal}_passes :",
            f"  exact_kernel_passes wp8s_kernel_{ordinal} = true.",
            "Proof. vm_compute. reflexivity. Qed.",
            f"Theorem wp8s_kernel_{ordinal}_metrics_match :",
            f"  exact_metrics_match wp8s_kernel_{ordinal} wp8s_metrics_{ordinal} = true.",
            "Proof. vm_compute. reflexivity. Qed.",
            "",
        ])
    bindings = ";\n    ".join(
        f"({rocq_string(key.encode())}, {rocq_string(value.encode())})"
        for key, value in certificate.bindings
    )
    lines.extend([
        "Definition wp8s_observation : residency_exact_observation :=",
        f"  {{| exact_bindings := [{bindings}];",
        f"     exact_claim_text := {rocq_string(certificate.claim)};",
        "     exact_scope := ExactObservedFourKernels;",
        "     exact_approval := ExactApprovalRecordedSnapshot;",
        "     exact_replay := ExactReplayAuthenticatedSnapshot;",
        "     exact_kernels := [wp8s_kernel_1; wp8s_kernel_2;",
        "                       wp8s_kernel_3; wp8s_kernel_4] |}.",
        "Theorem wp8s_exact_observation_is_admitted :",
        "  residency_exact_admitted wp8s_observation.",
        "Proof. repeat split; vm_compute; reflexivity. Qed.",
        "Corollary wp8s_observation_cannot_broaden :",
        "  exact_scope wp8s_observation <> WholeLanguagePerformance /\\",
        "  exact_scope wp8s_observation <> CrossImplementationComparison.",
        "Proof. apply exact_claim_cannot_broaden.",
        "  exact wp8s_exact_observation_is_admitted. Qed.",
        "Corollary wp8s_observation_cannot_reword :",
        "  exact_claim_text wp8s_observation = wp8s_reference_claim.",
        "Proof. apply exact_claim_cannot_reword.",
        "  exact wp8s_exact_observation_is_admitted. Qed.",
        "Corollary wp8s_observation_requires_approval_and_replay :",
        "  exact_approval wp8s_observation <> ExactApprovalAbsent /\\",
        "  exact_replay wp8s_observation <> ExactReplayAbsent.",
        "Proof. apply exact_claim_requires_approval_and_replay.",
        "  exact wp8s_exact_observation_is_admitted. Qed.",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--admission-report", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    # Invalid inputs leave an existing output untouched; never emit partial proof.
    try:
        certificate = authenticate(args.repo_root, args.admission_report, args.archive, args.receipt)
        source = emit_rocq(certificate)
        if args.output.exists():
            raise ExactClaimCertificateError("output already exists; choose a fresh path")
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(source)
    except (
        ExactClaimCertificateError, wp8s.ExactClaimError,
        wp8s.wp8p.ClaimAdmissionError, wp8s.wp8r.wp8q.PublicProtocolError,
        wp8s.wp8r.PublicBundleError, wp8s.wp8o.PairedThresholdError,
        wp8s.wp8r.wp8n.PairedEvidenceError, wp8s.wp8r.wp8n.wp8m.PairedRunnerError,
        wp8s.wp8r.wp8n.wp8m.wp8k.CandidateRunnerError,
        wp8s.wp8r.wp8n.wp8m.wp7c.RunnerError, OSError, ValueError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
