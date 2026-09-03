#!/usr/bin/env python3
"""Bind the sealed WP8J timing carrier to the proved WP8G process in Rocq.

The translator is intentionally untrusted.  It authenticates the exact WP8G
process report, WP8I static host boundary, WP8J candidate byte report, and
WP8J independent replay report.  Rocq receives only the reported timing prefix
and checks its bounded bytes, raw-clock syscall markers, role-four owner
marker, placement order, exact WP8G target suffix, execution prohibition, and
absence of performance-claim authority.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_host as wp8i
import s4_register_residency_process as wp8g
import s4_register_residency_timing as wp8j
import s4_residency_process_coq_certificate as process_bridge


class TimingCertificateError(RuntimeError):
    """The authenticated WP8J carrier cannot be joined to WP8G exactly."""


@dataclass(frozen=True)
class TimingReplayEvidence:
    report_root: str


@dataclass(frozen=True)
class TimingKernel:
    ordinal: str
    name: str
    prefix: tuple[int, ...]
    elf_bytes: int
    target_offset: int
    start_clock_offset: int
    end_clock_offset: int
    owner_offset: int


RAW_CLOCK_PREFIX = bytes.fromhex("b8e4000000bf04000000488d7424")
START_CLOCK_MARKER = RAW_CLOCK_PREFIX + bytes((0, 0x0F, 0x05))
END_CLOCK_MARKER = RAW_CLOCK_PREFIX + bytes((16, 0x0F, 0x05))
ROLE_FOUR_OWNER_MARKER = bytes.fromhex(
    "49b804000000000000004c89442448"
)


def _positions(haystack: bytes, needle: bytes) -> tuple[int, ...]:
    if not needle:
        raise TimingCertificateError("empty WP8J marker")
    return tuple(
        index
        for index in range(len(haystack) - len(needle) + 1)
        if haystack.startswith(needle, index)
    )


def parse_authenticated_timing_report(
    raw: bytes,
    admission: wp8j.Admission,
    candidate: wp8j.Candidate,
) -> TimingReplayEvidence:
    """Authenticate the exact WP8J non-executing replay report."""

    try:
        lines = wp8j._canonical(raw, "WP8J replay report")
    except wp8j.CandidateTimingError as error:
        raise TimingCertificateError(str(error)) from error
    if len(lines) != 12:
        raise TimingCertificateError("WP8J replay report extent drifted")
    prefix = (
        wp8j.REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"candidate-report-sha256\t{wp8j.CANDIDATE_REPORT_SHA256}",
        "mode\tindependent-byte-replay-no-execution",
        "status\tcandidate-timing-carrier-structurally-admitted",
        "execution-status\tforbidden",
        "claim-status\tnot-admitted",
        "role-owner\t4",
        "clock-reads\t2",
        "artifacts\t4",
    )
    if tuple(lines[: len(prefix)]) != prefix:
        raise TimingCertificateError("WP8J replay report metadata drifted")
    expected, expected_root = wp8j._report(
        admission.contract, admission.authority, candidate
    )
    if raw != expected:
        raise TimingCertificateError("WP8J replay report root drifted")
    marker = "report-root\t"
    if not lines[-1].startswith(marker):
        raise TimingCertificateError("WP8J replay report root is missing")
    report_root = lines[-1][len(marker) :]
    if report_root != expected_root:
        raise TimingCertificateError("WP8J replay report identity drifted")
    return TimingReplayEvidence(report_root)


def _verify_timing_layout(kernel: wp8j.Kernel) -> TimingKernel:
    record = kernel.record
    target = kernel.target
    elf = kernel.elf
    if (
        len(target) != record.target_bytes
        or wp8j._sha256(target) != record.target_hash
        or len(elf) != record.elf_bytes
        or wp8j._sha256(elf) != record.elf_hash
        or record.target_offset <= 0
        or elf[record.target_offset :] != target
    ):
        raise TimingCertificateError(
            f"{record.name} timing target or image identity drifted"
        )
    prefix = elf[: record.target_offset]
    raw_clock_positions = _positions(prefix, RAW_CLOCK_PREFIX)
    start_positions = _positions(prefix, START_CLOCK_MARKER)
    end_positions = _positions(prefix, END_CLOCK_MARKER)
    owner_positions = _positions(prefix, ROLE_FOUR_OWNER_MARKER)
    if (
        len(raw_clock_positions) != 2
        or len(start_positions) != 1
        or len(end_positions) != 1
        or len(owner_positions) != 1
        or not (
            start_positions[0]
            < end_positions[0]
            < owner_positions[0]
            < record.target_offset
        )
    ):
        raise TimingCertificateError(
            f"{record.name} clock or role-owner placement drifted"
        )
    return TimingKernel(
        ordinal=f"{record.ordinal:02}",
        name=record.name,
        prefix=tuple(prefix),
        elf_bytes=record.elf_bytes,
        target_offset=record.target_offset,
        start_clock_offset=start_positions[0],
        end_clock_offset=end_positions[0],
        owner_offset=owner_positions[0],
    )


def join_authenticated_carrier(
    timing_candidate: wp8j.Candidate,
    process_candidate: wp8g.Candidate,
) -> list[TimingKernel]:
    """Join every WP8J timing target to the exact WP8G process bytes."""

    process_targets = {
        (kernel.record.ordinal, kernel.record.name): kernel.process
        for kernel in process_candidate.kernels
    }
    if len(process_targets) != len(process_candidate.kernels):
        raise TimingCertificateError("WP8G process identity is duplicated")
    joined: list[TimingKernel] = []
    for kernel in timing_candidate.kernels:
        key = (kernel.record.ordinal, kernel.record.name)
        process = process_targets.get(key)
        if process is None or kernel.target != process:
            raise TimingCertificateError(
                f"{kernel.record.name} WP8J target is not the exact WP8G process"
            )
        joined.append(_verify_timing_layout(kernel))
    if len(joined) != len(process_targets):
        raise TimingCertificateError("WP8G/WP8J kernel extent drifted")
    return joined


def _coq_nat(value: int) -> str:
    return f"{value}%nat"


def _coq_list(values: tuple[int, ...]) -> str:
    return "[" + "; ".join(_coq_nat(value) for value in values) + "]"


def emit_rocq(
    kernels: list[TimingKernel],
    process_report_sha256: str,
    host_report_root: str,
    timing_candidate_sha256: str,
    timing_replay_root: str,
) -> str:
    modules = " ".join(
        f"GeneratedWP8GProcessKernel{kernel.ordinal}" for kernel in kernels
    )
    rows = [
        "(**",
        "  Generated from the sealed S4-WP8G through S4-WP8J artifacts.",
        f"  WP8G candidate SHA-256: {process_report_sha256}",
        f"  WP8I static host report root: {host_report_root}",
        f"  WP8J candidate SHA-256: {timing_candidate_sha256}",
        f"  WP8J replay report root: {timing_replay_root}",
        "  The generator is untrusted. Rocq checks the exact timing prefix,",
        "  target suffix, clock markers, role-four owner marker, placement,",
        "  byte bounds, execution prohibition, and no-claim boundary.",
        "  Syscall semantics, elapsed time, host eligibility, and benchmark",
        "  acquisition remain explicit non-claims.",
        "*)",
        "",
        "From Stdlib Require Import List Lia.",
        "From NauxCore Require Import ELF64ResidencyEnvelope",
        f"  ResidencyTimingCarrier {modules}.",
        "Import ListNotations.",
        "",
    ]
    for kernel in kernels:
        prefix = f"wp8j_kernel_{kernel.ordinal}"
        process = f"wp8g_kernel_{kernel.ordinal}_process"
        host = f"wp8g_kernel_{kernel.ordinal}_controlled_host_binding"
        rows.extend(
            [
                f"(** {kernel.name}; exact WP8J timing prefix. *)",
                f"Definition {prefix}_reported_prefix : list nat :=",
                f"  {_coq_list(kernel.prefix)}.",
                "",
                f"Definition {prefix}_timing_image : list nat :=",
                f"  {prefix}_reported_prefix ++ {process}.",
                "",
                f"Example {prefix}_reported_prefix_extent :",
                f"  length {prefix}_reported_prefix =",
                f"    {_coq_nat(kernel.target_offset)}.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Example {prefix}_timing_image_extent :",
                f"  length {prefix}_timing_image = {_coq_nat(kernel.elf_bytes)}.",
                "Proof.",
                f"  unfold {prefix}_timing_image.",
                "  rewrite app_length,",
                f"    {prefix}_reported_prefix_extent,",
                f"    wp8g_kernel_{kernel.ordinal}_process_extent.",
                "  reflexivity.",
                "Qed.",
                "",
                f"Example {prefix}_reported_prefix_bytes_check :",
                "  forallb elf64_residency_byte_validb",
                f"    {prefix}_reported_prefix = true.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Theorem {prefix}_reported_prefix_bytes_are_bounded :",
                "  Forall (fun byte => (byte < 256)%nat)",
                f"    {prefix}_reported_prefix.",
                "Proof.",
                "  apply elf64_residency_bytes_check_sound.",
                f"  exact {prefix}_reported_prefix_bytes_check.",
                "Qed.",
                "",
                f"Theorem {prefix}_timing_image_bytes_are_bounded :",
                "  Forall (fun byte => (byte < 256)%nat)",
                f"    {prefix}_timing_image.",
                "Proof.",
                f"  unfold {prefix}_timing_image.",
                "  apply Forall_app. split.",
                f"  - exact {prefix}_reported_prefix_bytes_are_bounded.",
                f"  - exact wp8g_kernel_{kernel.ordinal}_process_bytes_are_bounded.",
                "Qed.",
                "",
                f"Definition {prefix}_carrier : residency_timing_carrier :=",
                f"  {{| residency_carrier_host_binding := {host};",
                f"     residency_carrier_target := {process};",
                f"     residency_carrier_prefix := {prefix}_reported_prefix;",
                f"     residency_carrier_image := {prefix}_timing_image;",
                "     residency_carrier_target_offset :=",
                f"       {_coq_nat(kernel.target_offset)};",
                "     residency_carrier_start_clock_offset :=",
                f"       {_coq_nat(kernel.start_clock_offset)};",
                "     residency_carrier_end_clock_offset :=",
                f"       {_coq_nat(kernel.end_clock_offset)};",
                "     residency_carrier_owner_offset :=",
                f"       {_coq_nat(kernel.owner_offset)};",
                "     residency_carrier_role_owner := 4%nat;",
                "     residency_carrier_clock_source_value :=",
                "       ResidencyClockMonotonicRaw;",
                "     residency_carrier_clock_reads := 2%nat;",
                "     residency_carrier_clock_placement_value :=",
                "       ResidencyClockBeforeTargetAfterValidation;",
                "     residency_carrier_execution :=",
                "       ResidencyCarrierExecutionForbidden;",
                "     residency_carrier_claim :=",
                "       ResidencyPerformanceClaimForbidden |}.",
                "",
                f"Example {prefix}_start_clock_marker_check :",
                "  residency_sublist_atb",
                f"    {_coq_nat(kernel.start_clock_offset)}",
                "    (residency_monotonic_raw_clock_marker 0)",
                f"    {prefix}_reported_prefix = true.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Example {prefix}_end_clock_marker_check :",
                "  residency_sublist_atb",
                f"    {_coq_nat(kernel.end_clock_offset)}",
                "    (residency_monotonic_raw_clock_marker 16)",
                f"    {prefix}_reported_prefix = true.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Example {prefix}_owner_marker_check :",
                "  residency_sublist_atb",
                f"    {_coq_nat(kernel.owner_offset)}",
                "    residency_role_four_owner_marker",
                f"    {prefix}_reported_prefix = true.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Example {prefix}_clock_marker_count_check :",
                "  residency_sublist_count residency_monotonic_raw_clock_prefix",
                f"    {prefix}_reported_prefix = 2%nat.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Example {prefix}_marker_order_check :",
                f"  ({_coq_nat(kernel.start_clock_offset)} <",
                f"   {_coq_nat(kernel.end_clock_offset)})%nat /\\",
                f"  ({_coq_nat(kernel.end_clock_offset)} <",
                f"   {_coq_nat(kernel.owner_offset)})%nat /\\",
                f"  ({_coq_nat(kernel.owner_offset)} <",
                f"   {_coq_nat(kernel.target_offset)})%nat.",
                "Proof. vm_compute. lia. Qed.",
                "",
                f"Theorem {prefix}_prefix_is_well_formed :",
                f"  residency_timing_prefix_well_formed {prefix}_carrier.",
                "Proof.",
                "  unfold residency_timing_prefix_well_formed,",
                f"    {prefix}_carrier.",
                f"  split; [exact {prefix}_start_clock_marker_check |].",
                f"  split; [exact {prefix}_end_clock_marker_check |].",
                f"  split; [exact {prefix}_owner_marker_check |].",
                f"  split; [exact {prefix}_clock_marker_count_check |].",
                f"  exact {prefix}_marker_order_check.",
                "Qed.",
                "",
                f"Theorem {prefix}_carrier_is_admitted :",
                f"  residency_timing_carrier_admitted {prefix}_carrier.",
                "Proof.",
                "  unfold residency_timing_carrier_admitted,",
                f"    {prefix}_carrier.",
                "  split.",
                f"  - exact wp8g_kernel_{kernel.ordinal}_static_host_boundary_is_admitted.",
                "  - split; [reflexivity |].",
                "    split; [reflexivity |].",
                f"    split; [exact {prefix}_reported_prefix_extent |].",
                f"    split; [exact {prefix}_reported_prefix_bytes_are_bounded |].",
                f"    split; [exact {prefix}_timing_image_bytes_are_bounded |].",
                f"    split; [exact {prefix}_prefix_is_well_formed |].",
                "    split; [reflexivity |].",
                "    split; [reflexivity |].",
                "    split; [reflexivity |].",
                "    split; [reflexivity |].",
                "    split; reflexivity.",
                "Qed.",
                "",
                f"Corollary {prefix}_contains_exact_process :",
                f"  skipn {_coq_nat(kernel.target_offset)}",
                f"    {prefix}_timing_image = {process}.",
                "Proof.",
                "  exact (residency_timing_carrier_contains_exact_target",
                f"    {prefix}_carrier {prefix}_carrier_is_admitted).",
                "Qed.",
                "",
                f"Corollary {prefix}_is_not_runnable :",
                f"  ~ residency_timing_carrier_runnable {prefix}_carrier.",
                "Proof.",
                "  exact (residency_timing_carrier_is_not_runnable",
                f"    {prefix}_carrier {prefix}_carrier_is_admitted).",
                "Qed.",
                "",
                f"Corollary {prefix}_has_no_performance_claim :",
                f"  residency_carrier_claim {prefix}_carrier =",
                "    ResidencyPerformanceClaimForbidden.",
                "Proof.",
                "  exact (residency_timing_carrier_has_no_performance_claim",
                f"    {prefix}_carrier {prefix}_carrier_is_admitted).",
                "Qed.",
                "",
            ]
        )
    return "\n".join(rows)


def _filter_kernels(
    kernels: list[TimingKernel], requested_ordinals: list[str] | None
) -> list[TimingKernel]:
    if not requested_ordinals:
        return kernels
    requested = set(requested_ordinals)
    if len(requested) != len(requested_ordinals):
        raise TimingCertificateError("duplicate --kernel ordinal")
    missing = requested - {kernel.ordinal for kernel in kernels}
    if missing:
        raise TimingCertificateError(
            "unknown --kernel ordinal: " + ", ".join(sorted(missing))
        )
    return [kernel for kernel in kernels if kernel.ordinal in requested]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--process-report", required=True, type=Path)
    parser.add_argument("--host-report", required=True, type=Path)
    parser.add_argument("--timing-candidate", required=True, type=Path)
    parser.add_argument("--timing-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--kernel",
        action="append",
        help="emit only this two-digit kernel ordinal (repeatable)",
    )
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    arguments = parser.parse_args()
    try:
        root = arguments.repo_root.resolve(strict=True)
        process_admission = wp8g.validate(root)
        host_admission = wp8i.validate(root)
        timing_admission = wp8j.validate(root)
        if (
            timing_admission.role.authority.seal
            != host_admission.candidate.authority.seal
        ):
            raise TimingCertificateError("WP8I/WP8J candidate role identity drifted")

        process_raw = arguments.process_report.read_bytes()
        host_raw = arguments.host_report.read_bytes()
        timing_raw = arguments.timing_candidate.read_bytes()
        timing_report_raw = arguments.timing_report.read_bytes()
        process_candidate = wp8g.parse_candidate(
            process_raw, process_admission.contract
        )
        process_bridge.parse_authenticated_host_report(host_raw, host_admission)
        timing_candidate = wp8j.parse_candidate(
            timing_raw, timing_admission.contract
        )
        timing_evidence = parse_authenticated_timing_report(
            timing_report_raw, timing_admission, timing_candidate
        )
        kernels = _filter_kernels(
            join_authenticated_carrier(timing_candidate, process_candidate),
            arguments.kernel,
        )
        output = emit_rocq(
            kernels,
            wp8g.CANDIDATE_REPORT_SHA256,
            host_admission.static_root,
            wp8j.CANDIDATE_REPORT_SHA256,
            timing_evidence.report_root,
        )
        arguments.output.write_text(output, encoding="utf-8", newline="\n")
    except (
        TimingCertificateError,
        process_bridge.ProcessCertificateError,
        wp8g.ProcessReplayError,
        wp8g.wp8f.ElfAuthorityError,
        wp8i.CandidateHostError,
        wp8i.wp6.HostControlError,
        wp8j.CandidateTimingError,
        wp8j.wp7b.TimingReplayError,
        OSError,
        ValueError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
