#!/usr/bin/env python3
"""Bind admitted WP8F ELF64 images to admitted WP8E target bytes in Rocq.

The translator is intentionally untrusted.  It authenticates the sealed
WP8C, WP8E, and WP8F reports, independently reconstructs each canonical ELF
envelope, and emits the complete image bytes.  Rocq then checks byte equality
against its own envelope constructor around the already checked WP8E target.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_candidate_authority as wp8e
import s4_register_residency_elf_authority as wp8f
import s4_register_residency_plan_authority as wp8c
import s4_residency_coq_certificate as semantic
import s4_residency_x86_coq_certificate as x86_bridge


class ElfCertificateError(RuntimeError):
    """The admitted WP8E and WP8F reports cannot form a closed certificate."""


@dataclass(frozen=True)
class ElfKernel:
    ordinal: str
    name: str
    image: tuple[int, ...]
    image_bytes: int
    target_bytes: int
    target_offset: int
    entry: int
    load_flags: int
    stack_flags: int


def _unsigned(raw: str, label: str) -> int:
    if not raw or not raw.isascii() or not raw.isdigit():
        raise ElfCertificateError(f"{label} is not an unsigned integer")
    if raw != "0" and raw.startswith("0"):
        raise ElfCertificateError(f"{label} is not canonical")
    return int(raw)


def _canonical_lines(raw: bytes, label: str) -> list[str]:
    if not raw or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise ElfCertificateError(f"{label} has invalid extent or encoding")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ElfCertificateError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise ElfCertificateError(f"{label} contains blank or padded rows")
    return lines


def _le16(value: int) -> bytes:
    return value.to_bytes(2, "little", signed=False)


def _le32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=False)


def _le64(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def canonical_elf64_envelope(target: bytes) -> bytes:
    """Independently reconstruct the exact WP8F linker-free envelope."""

    image_bytes = 272 + len(target)
    header = b"".join(
        (
            b"\x7fELF\x02\x01\x01" + bytes(9),
            _le16(2),
            _le16(62),
            _le32(1),
            _le64(4_194_560),
            _le64(64),
            _le64(0),
            _le32(0),
            _le16(64),
            _le16(56),
            _le16(2),
            _le16(0),
            _le16(0),
            _le16(0),
        )
    )
    load = b"".join(
        (
            _le32(1),
            _le32(5),
            _le64(0),
            _le64(4_194_304),
            _le64(4_194_304),
            _le64(image_bytes),
            _le64(image_bytes),
            _le64(4_096),
        )
    )
    stack = b"".join(
        (
            _le32(0x6474_E551),
            _le32(6),
            bytes(40),
            _le64(16),
        )
    )
    startup = bytes.fromhex("e80b00000031ffb83c0000000f050f0b")
    envelope = header + load + stack + bytes(80) + startup + target
    if len(header) != 64 or len(load) != 56 or len(stack) != 56:
        raise ElfCertificateError("internal ELF field extent drifted")
    if len(envelope) != image_bytes:
        raise ElfCertificateError("internal ELF envelope extent drifted")
    return envelope


def parse_joined_elf_report(
    raw: bytes,
    native_kernels: list[x86_bridge.NativeKernel],
    expected_root: str,
) -> list[ElfKernel]:
    lines = _canonical_lines(raw, "WP8F report")
    if lines[0] != wp8f.ELF_MAGIC:
        raise ElfCertificateError("WP8F report magic drifted")
    expected_metadata = [
        f"meta\t{key}\t{value}" for key, value in wp8f.EXPECTED_METADATA
    ]
    if lines[1:9] != expected_metadata or lines[9] != wp8f.EXPECTED_COLUMNS:
        raise ElfCertificateError("WP8F report metadata or columns drifted")

    index = 10
    kernels: list[ElfKernel] = []
    for native in native_kernels:
        fields = lines[index].split("\t")
        index += 1
        if len(fields) != 13 or fields[:3] != ["kernel", native.ordinal, native.name]:
            raise ElfCertificateError("WP8E/WP8F kernel identity drifted")
        target_bytes = _unsigned(fields[7], "WP8F target bytes")
        image_bytes = _unsigned(fields[8], "WP8F image bytes")
        target_offset = _unsigned(fields[9], "WP8F target offset")
        entry = _unsigned(fields[10], "WP8F entry")
        load_flags = _unsigned(fields[11], "WP8F load flags")
        stack_flags = _unsigned(fields[12], "WP8F stack flags")

        image_fields = lines[index].split("\t")
        index += 1
        if image_fields[:2] != ["elf-hex", native.ordinal] or len(image_fields) != 3:
            raise ElfCertificateError("WP8F image row is malformed")
        try:
            image = bytes.fromhex(image_fields[2])
        except ValueError as error:
            raise ElfCertificateError("WP8F image hex is malformed") from error

        target = bytes(native.target)
        if (
            target_bytes != len(target)
            or image_bytes != len(image)
            or target_offset != 272
            or image_bytes != target_offset + target_bytes
            or entry != 4_194_560
            or load_flags != 5
            or stack_flags != 6
        ):
            raise ElfCertificateError("WP8F structural receipt drifted")
        if image[target_offset:] != target:
            raise ElfCertificateError("WP8F image does not contain the WP8E target")
        if image != canonical_elf64_envelope(target):
            raise ElfCertificateError("WP8F image is not the canonical ELF64 envelope")
        kernels.append(
            ElfKernel(
                ordinal=native.ordinal,
                name=native.name,
                image=tuple(image),
                image_bytes=image_bytes,
                target_bytes=target_bytes,
                target_offset=target_offset,
                entry=entry,
                load_flags=load_flags,
                stack_flags=stack_flags,
            )
        )

    if lines[index : index + 2] != [
        "verification\tindependent-elf-parser-accepted",
        "verification\tno-file-no-execution-no-measurement",
    ]:
        raise ElfCertificateError("WP8F verification surface drifted")
    if index + 3 != len(lines) or lines[index + 2] != f"report-root\t{expected_root}":
        raise ElfCertificateError("WP8F report tail drifted")
    return kernels


def _coq_nat(value: int) -> str:
    return f"{value}%nat"


def _coq_list(values: tuple[int, ...]) -> str:
    return "[" + "; ".join(_coq_nat(value) for value in values) + "]"


def emit_rocq(
    kernels: list[ElfKernel],
    plan_root: str,
    encoding_root: str,
    elf_root: str,
) -> str:
    rows = [
        "(**",
        "  Generated from the sealed S4-WP8C, S4-WP8E, and S4-WP8F reports.",
        f"  WP8C report root: {plan_root}",
        f"  WP8E report root: {encoding_root}",
        f"  WP8F report root: {elf_root}",
        "  The generator is untrusted. Rocq receives every complete ELF image",
        "  and proves byte equality to its own canonical envelope around the",
        "  already checked WP8E target bytes.",
        "  Linux loading, system calls, x86 execution, native correctness,",
        "  timing, and performance remain explicit non-claims.",
        "*)",
        "",
        "From Stdlib Require Import List.",
        "From NauxCore Require Import ELF64ResidencyEnvelope",
        "  GeneratedWP8EX86Certificates.",
        "Import ListNotations.",
        "",
    ]
    for kernel in kernels:
        prefix = f"wp8f_kernel_{kernel.ordinal}"
        wp8e_target = f"wp8e_kernel_{kernel.ordinal}_target"
        reported_prefix = kernel.image[: kernel.target_offset]
        reported_target = kernel.image[kernel.target_offset :]
        rows.extend(
            [
                f"(** {kernel.name}; complete quarantined ELF64 image bytes. *)",
                f"Definition {prefix}_reported_prefix : list nat :=",
                f"  {_coq_list(reported_prefix)}.",
                "",
                f"Definition {prefix}_reported_target : list nat :=",
                f"  {_coq_list(reported_target)}.",
                "",
                f"Definition {prefix}_image : list nat :=",
                f"  {prefix}_reported_prefix ++ {prefix}_reported_target.",
                "",
                f"Example {prefix}_reported_prefix_extent :",
                f"  length {prefix}_reported_prefix =",
                f"    {_coq_nat(kernel.target_offset)}.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Example {prefix}_reported_target_matches_wp8e :",
                f"  {prefix}_reported_target = {wp8e_target}.",
                "Proof. reflexivity. Qed.",
                "",
                f"Example {prefix}_reported_prefix_is_canonical :",
                f"  {prefix}_reported_prefix =",
                f"    elf64_residency_prefix {_coq_nat(kernel.image_bytes)}.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Example {prefix}_image_extent :",
                f"  length {prefix}_image = {_coq_nat(kernel.image_bytes)}.",
                "Proof.",
                f"  unfold {prefix}_image. rewrite length_app.",
                f"  rewrite {prefix}_reported_prefix_extent.",
                f"  rewrite {prefix}_reported_target_matches_wp8e.",
                f"  rewrite wp8e_kernel_{kernel.ordinal}_target_extent.",
                "  reflexivity.",
                "Qed.",
                "",
                f"Definition {prefix}_target_offset : nat :=",
                f"  {_coq_nat(kernel.target_offset)}.",
                f"Definition {prefix}_entry : nat := {_coq_nat(kernel.entry)}.",
                f"Definition {prefix}_load_flags : nat := {_coq_nat(kernel.load_flags)}.",
                f"Definition {prefix}_stack_flags : nat := {_coq_nat(kernel.stack_flags)}.",
                "",
                f"Example {prefix}_reported_prefix_bytes_check :",
                "  forallb elf64_residency_byte_validb",
                f"    {prefix}_reported_prefix = true.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Theorem {prefix}_reported_bytes_are_bounded :",
                f"  Forall (fun byte => byte < 256) {prefix}_image.",
                "Proof.",
                f"  unfold {prefix}_image.",
                "  apply Forall_app. split.",
                "  - apply elf64_residency_bytes_check_sound.",
                f"    exact {prefix}_reported_prefix_bytes_check.",
                f"  - rewrite {prefix}_reported_target_matches_wp8e.",
                f"    exact wp8e_kernel_{kernel.ordinal}_target_bytes_are_bounded.",
                "Qed.",
                "",
                f"Theorem {prefix}_image_equals_canonical_envelope :",
                f"  {prefix}_image = elf64_residency_envelope {wp8e_target}.",
                "Proof.",
                f"  unfold {prefix}_image, elf64_residency_envelope.",
                f"  rewrite {prefix}_reported_target_matches_wp8e.",
                f"  rewrite wp8e_kernel_{kernel.ordinal}_target_extent.",
                f"  rewrite {prefix}_reported_prefix_is_canonical.",
                "  reflexivity.",
                "Qed.",
                "",
                f"Theorem {prefix}_image_is_canonical_envelope :",
                f"  elf64_residency_image_well_formed {wp8e_target}",
                f"    {prefix}_image.",
                "Proof. split.",
                f"  - exact {prefix}_reported_bytes_are_bounded.",
                f"  - exact {prefix}_image_equals_canonical_envelope.",
                "Qed.",
                "",
                f"Corollary {prefix}_contains_wp8e_target :",
                f"  skipn {_coq_nat(kernel.target_offset)} {prefix}_image =",
                f"    {wp8e_target}.",
                "Proof.",
                f"  change skipn 272%nat {prefix}_image = {wp8e_target}.",
                "  apply elf64_residency_well_formed_contains_target.",
                f"  exact {prefix}_image_is_canonical_envelope.",
                "Qed.",
                "",
            ]
        )
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-report", required=True, type=Path)
    parser.add_argument("--encoding-report", required=True, type=Path)
    parser.add_argument("--elf-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    arguments = parser.parse_args()
    try:
        root = arguments.repo_root.resolve(strict=True)
        plan_admission = wp8c.validate(root, arguments.plan_report)
        _, encoding_admission, _, _ = wp8e.validate(root, arguments.encoding_report)
        _, elf_admission, _, _ = wp8f.validate(root, arguments.elf_report)
        plan_raw = arguments.plan_report.read_bytes()
        encoding_raw = arguments.encoding_report.read_bytes()
        elf_raw = arguments.elf_report.read_bytes()
        plan_kernels = semantic.parse_verified_report(plan_raw)
        wp8d_admission = wp8e.wp8d.validate(root)
        native_kernels = x86_bridge.parse_joined_reports(
            plan_raw,
            encoding_raw,
            plan_kernels,
            wp8d_admission.contract.kernels,
        )
        kernels = parse_joined_elf_report(
            elf_raw, native_kernels, elf_admission.root
        )
        output = emit_rocq(
            kernels,
            plan_admission.plan.root,
            encoding_admission.root,
            elf_admission.root,
        )
        arguments.output.write_text(output, encoding="utf-8", newline="\n")
    except (
        ElfCertificateError,
        semantic.CertificateError,
        x86_bridge.X86CertificateError,
        wp8c.PlanAuthorityError,
        wp8e.CandidateAuthorityError,
        wp8e.wp8d.EncodingContractError,
        wp8f.ElfAuthorityError,
        OSError,
        ValueError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
