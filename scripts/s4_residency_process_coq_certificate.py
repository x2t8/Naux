#!/usr/bin/env python3
"""Bind the admitted WP8G process rewrite to WP8E bytes in Rocq.

The translator is intentionally untrusted.  It authenticates the WP8C and
WP8E reports plus the sealed WP8G authority and candidate report.  It emits
only the WP8G-owned sixteen-byte return patch, eighty-byte verifier, and
closed receipts.  Rocq reuses the complete WP8E target and checks the rewrite,
jump destination, verifier fields, failure edges, extent, and byte bounds.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_candidate_authority as wp8e
import s4_register_residency_plan_authority as wp8c
import s4_register_residency_process as wp8g
import s4_residency_coq_certificate as semantic
import s4_residency_x86_coq_certificate as x86_bridge


class ProcessCertificateError(RuntimeError):
    """The admitted WP8E and WP8G artifacts cannot be joined exactly."""


@dataclass(frozen=True)
class ProcessKernel:
    ordinal: str
    name: str
    patch: tuple[int, ...]
    verifier: tuple[int, ...]
    process_bytes: int
    return_start: int
    verifier_offset: int
    error_offset: int
    promoted_displacement: int
    checksum_displacement: int
    outer_displacement: int
    inner_displacement: int
    owner_displacement: int
    expected_outer: int
    expected_inner: int
    outer_error_delta: int
    inner_error_delta: int
    owner_error_delta: int


def _signed_le32(raw: bytes, label: str) -> int:
    if len(raw) != 4:
        raise ProcessCertificateError(f"{label} is not four bytes")
    return int.from_bytes(raw, "little", signed=True)


def join_authenticated_candidate(
    candidate: wp8g.Candidate,
    native_kernels: list[x86_bridge.NativeKernel],
) -> list[ProcessKernel]:
    """Join an already authenticated WP8G candidate to its WP8E parents."""

    native_by_ordinal = {kernel.ordinal: kernel for kernel in native_kernels}
    if len(native_by_ordinal) != len(native_kernels):
        raise ProcessCertificateError("WP8E contains duplicate kernel ordinals")

    joined: list[ProcessKernel] = []
    for kernel in candidate.kernels:
        record = kernel.record
        ordinal = f"{record.ordinal:02}"
        native = native_by_ordinal.get(ordinal)
        if native is None or native.name != record.name:
            raise ProcessCertificateError("WP8E/WP8G kernel identity drifted")
        candidate_bytes = bytes(kernel.candidate)
        process = bytes(kernel.process)
        if candidate_bytes != bytes(native.target):
            raise ProcessCertificateError("WP8G candidate is not the admitted WP8E target")
        if record.verifier_offset != len(candidate_bytes):
            raise ProcessCertificateError("WP8G verifier does not follow the WP8E target")

        return_end = record.return_start + 16
        patch = process[record.return_start:return_end]
        verifier = process[record.verifier_offset:]
        if len(patch) != 16 or len(verifier) != 80:
            raise ProcessCertificateError("WP8G patch or verifier extent drifted")
        if (
            patch[:1] != b"\xe9"
            or patch[5:] != b"\x90" * 11
            or verifier[27:29] != b"\x0f\x85"
            or verifier[49:51] != b"\x0f\x85"
            or verifier[65:67] != b"\x0f\x85"
        ):
            raise ProcessCertificateError("WP8G control-transfer encoding drifted")

        promoted = _signed_le32(
            candidate_bytes[record.return_start + 3:record.return_start + 7],
            "WP8E promoted displacement",
        )
        if promoted != record.inner_displacement:
            raise ProcessCertificateError("WP8G promoted displacement drifted")
        joined.append(
            ProcessKernel(
                ordinal=ordinal,
                name=record.name,
                patch=tuple(patch),
                verifier=tuple(verifier),
                process_bytes=record.process_bytes,
                return_start=record.return_start,
                verifier_offset=record.verifier_offset,
                error_offset=record.error_offset,
                promoted_displacement=promoted,
                checksum_displacement=record.checksum_displacement,
                outer_displacement=record.outer_displacement,
                inner_displacement=record.inner_displacement,
                owner_displacement=record.owner_displacement,
                expected_outer=record.expected_outer,
                expected_inner=record.expected_inner,
                outer_error_delta=_signed_le32(verifier[29:33], "outer error delta"),
                inner_error_delta=_signed_le32(verifier[51:55], "inner error delta"),
                owner_error_delta=_signed_le32(verifier[67:71], "owner error delta"),
            )
        )

    if len(joined) != len(native_kernels):
        raise ProcessCertificateError("WP8G kernel extent does not match WP8E")
    return joined


def _coq_nat(value: int) -> str:
    return f"{value}%nat"


def _coq_z(value: int) -> str:
    return f"({value}%Z)" if value < 0 else f"{value}%Z"


def _coq_list(values: tuple[int, ...]) -> str:
    return "[" + "; ".join(_coq_nat(value) for value in values) + "]"


def emit_rocq(
    kernels: list[ProcessKernel],
    plan_root: str,
    encoding_root: str,
    process_report_sha256: str,
    process_authority_root: str,
) -> str:
    rows = [
        "(**",
        "  Generated from the sealed S4-WP8C, S4-WP8E, and S4-WP8G artifacts.",
        f"  WP8C report root: {plan_root}",
        f"  WP8E report root: {encoding_root}",
        f"  WP8G candidate SHA-256: {process_report_sha256}",
        f"  WP8G authority report root: {process_authority_root}",
        "  The generator is untrusted. Rocq receives only WP8G-owned patch and",
        "  verifier bytes, reuses the checked WP8E target, and validates the",
        "  exact rewrite structure and all closed receipt equations.",
        "  x86 execution, Linux loading, syscalls, timing, and performance",
        "  remain explicit non-claims.",
        "*)",
        "",
        "From Stdlib Require Import List ZArith Lia.",
        "From NauxCore Require Import X86ResidencyEncoding ResidencyProcessTarget",
        "  GeneratedWP8EX86Certificates.",
        "Import ListNotations.",
        "Open Scope Z_scope.",
        "",
    ]
    for kernel in kernels:
        prefix = f"wp8g_kernel_{kernel.ordinal}"
        wp8e_target = f"wp8e_kernel_{kernel.ordinal}_target"
        rows.extend(
            [
                f"(** {kernel.name}; exact process-target return rewrite. *)",
                f"Definition {prefix}_patch : list nat :=",
                f"  {_coq_list(kernel.patch)}.",
                "",
                f"Definition {prefix}_verifier : list nat :=",
                f"  {_coq_list(kernel.verifier)}.",
                "",
                f"Definition {prefix}_receipt : residency_process_receipt :=",
                "  {| residency_process_return_start := "
                f"{_coq_nat(kernel.return_start)};",
                "     residency_process_verifier_offset := "
                f"{_coq_nat(kernel.verifier_offset)};",
                "     residency_process_error_offset := "
                f"{_coq_nat(kernel.error_offset)};",
                "     residency_process_promoted_displacement := "
                f"{_coq_z(kernel.promoted_displacement)};",
                "     residency_process_checksum_displacement := "
                f"{_coq_z(kernel.checksum_displacement)};",
                "     residency_process_outer_displacement := "
                f"{_coq_z(kernel.outer_displacement)};",
                "     residency_process_inner_displacement := "
                f"{_coq_z(kernel.inner_displacement)};",
                "     residency_process_owner_displacement := "
                f"{_coq_z(kernel.owner_displacement)};",
                "     residency_process_expected_outer := "
                f"{_coq_nat(kernel.expected_outer)};",
                "     residency_process_expected_inner := "
                f"{_coq_nat(kernel.expected_inner)} |}}.",
                "",
                f"Definition {prefix}_completion : residency_completion_verifier :=",
                "  {| residency_completion_checksum_displacement := "
                f"{_coq_z(kernel.checksum_displacement)};",
                "     residency_completion_outer_displacement := "
                f"{_coq_z(kernel.outer_displacement)};",
                "     residency_completion_expected_outer := "
                f"{_coq_nat(kernel.expected_outer)};",
                "     residency_completion_outer_error_delta := "
                f"{_coq_z(kernel.outer_error_delta)};",
                "     residency_completion_expected_inner := "
                f"{_coq_nat(kernel.expected_inner)};",
                "     residency_completion_inner_error_delta := "
                f"{_coq_z(kernel.inner_error_delta)};",
                "     residency_completion_owner_displacement := "
                f"{_coq_z(kernel.owner_displacement)};",
                "     residency_completion_owner_error_delta := "
                f"{_coq_z(kernel.owner_error_delta)};",
                "     residency_completion_promoted_displacement := "
                f"{_coq_z(kernel.promoted_displacement)} |}}.",
                "",
                f"Definition {prefix}_process : list nat :=",
                "  residency_process_target",
                f"    {wp8e_target} {prefix}_patch {prefix}_verifier",
                f"    {_coq_nat(kernel.return_start)}.",
                "",
                f"Example {prefix}_patch_bytes_check :",
                f"  forallb x86_byte_validb {prefix}_patch = true.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Theorem {prefix}_patch_bytes_are_bounded :",
                f"  Forall (fun byte => (byte < 256)%nat) {prefix}_patch.",
                "Proof.",
                "  apply x86_bytes_check_sound.",
                f"  exact {prefix}_patch_bytes_check.",
                "Qed.",
                "",
                f"Example {prefix}_verifier_bytes_check :",
                f"  forallb x86_byte_validb {prefix}_verifier = true.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Theorem {prefix}_verifier_bytes_are_bounded :",
                f"  Forall (fun byte => (byte < 256)%nat) {prefix}_verifier.",
                "Proof.",
                "  apply x86_bytes_check_sound.",
                f"  exact {prefix}_verifier_bytes_check.",
                "Qed.",
                "",
                f"Theorem {prefix}_process_is_well_formed :",
                "  residency_process_target_well_formed",
                f"    {wp8e_target} {prefix}_patch {prefix}_verifier",
                f"    {prefix}_process {prefix}_receipt {prefix}_completion.",
                "Proof.",
                "  constructor.",
                f"  - rewrite wp8e_kernel_{kernel.ordinal}_target_extent.",
                "    vm_compute. lia.",
                f"  - rewrite wp8e_kernel_{kernel.ordinal}_target_extent.",
                "    reflexivity.",
                "  - vm_compute. reflexivity.",
                "  - vm_compute. reflexivity.",
                "  - vm_compute. reflexivity.",
                "  - vm_compute. reflexivity.",
                "  - vm_compute. reflexivity.",
                "  - vm_compute. repeat split; reflexivity.",
                "  - vm_compute. repeat split; reflexivity.",
                f"  - exact {prefix}_patch_bytes_are_bounded.",
                f"  - exact {prefix}_verifier_bytes_are_bounded.",
                "  - reflexivity.",
                "Qed.",
                "",
                f"Theorem {prefix}_process_extent :",
                f"  length {prefix}_process = {_coq_nat(kernel.process_bytes)}.",
                "Proof.",
                "  apply residency_process_target_extent with",
                f"    (receipt := {prefix}_receipt)",
                f"    (completion := {prefix}_completion).",
                f"  exact {prefix}_process_is_well_formed.",
                "Qed.",
                "",
                f"Theorem {prefix}_contains_verifier :",
                f"  skipn (length {wp8e_target}) {prefix}_process =",
                f"    {prefix}_verifier.",
                "Proof.",
                "  apply residency_process_target_contains_verifier with",
                f"    (receipt := {prefix}_receipt)",
                f"    (completion := {prefix}_completion).",
                f"  exact {prefix}_process_is_well_formed.",
                "Qed.",
                "",
                f"Theorem {prefix}_process_bytes_are_bounded :",
                f"  Forall (fun byte => (byte < 256)%nat) {prefix}_process.",
                "Proof.",
                "  apply residency_process_target_bytes_are_bounded with",
                f"    (receipt := {prefix}_receipt)",
                f"    (completion := {prefix}_completion).",
                f"  - exact wp8e_kernel_{kernel.ordinal}_target_bytes_are_bounded.",
                f"  - exact {prefix}_process_is_well_formed.",
                "Qed.",
                "",
            ]
        )
    return "\n".join(rows)


def _filter_kernels(
    kernels: list[ProcessKernel], requested_ordinals: list[str] | None
) -> list[ProcessKernel]:
    if not requested_ordinals:
        return kernels
    requested = set(requested_ordinals)
    if len(requested) != len(requested_ordinals):
        raise ProcessCertificateError("duplicate --kernel ordinal")
    missing = requested - {kernel.ordinal for kernel in kernels}
    if missing:
        raise ProcessCertificateError(
            "unknown --kernel ordinal: " + ", ".join(sorted(missing))
        )
    return [kernel for kernel in kernels if kernel.ordinal in requested]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-report", required=True, type=Path)
    parser.add_argument("--encoding-report", required=True, type=Path)
    parser.add_argument("--process-report", required=True, type=Path)
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
        plan_admission = wp8c.validate(root, arguments.plan_report)
        _, encoding_admission, _, _ = wp8e.validate(root, arguments.encoding_report)
        process_admission = wp8g.validate(root)

        plan_raw = arguments.plan_report.read_bytes()
        encoding_raw = arguments.encoding_report.read_bytes()
        process_raw = arguments.process_report.read_bytes()
        plan_kernels = semantic.parse_verified_report(plan_raw)
        wp8d_admission = wp8e.wp8d.validate(root)
        native_kernels = x86_bridge.parse_joined_reports(
            plan_raw,
            encoding_raw,
            plan_kernels,
            wp8d_admission.contract.kernels,
        )
        process_candidate = wp8g.parse_candidate(
            process_raw, process_admission.contract
        )
        kernels = _filter_kernels(
            join_authenticated_candidate(process_candidate, native_kernels),
            arguments.kernel,
        )
        output = emit_rocq(
            kernels,
            plan_admission.plan.root,
            encoding_admission.root,
            wp8g.CANDIDATE_REPORT_SHA256,
            process_admission.report_root,
        )
        arguments.output.write_text(output, encoding="utf-8", newline="\n")
    except (
        ProcessCertificateError,
        semantic.CertificateError,
        x86_bridge.X86CertificateError,
        wp8c.PlanAuthorityError,
        wp8e.CandidateAuthorityError,
        wp8e.wp8d.EncodingContractError,
        wp8g.ProcessReplayError,
        wp8g.wp8f.ElfAuthorityError,
        OSError,
        ValueError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
