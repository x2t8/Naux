#!/usr/bin/env python3
"""Bind the admitted WP8G process through the WP8I host boundary in Rocq.

The translator is intentionally untrusted.  It authenticates the WP8C and
WP8E reports plus the sealed WP8G process, WP8H role, and WP8I static host
reports.  It emits only the WP8G-owned sixteen-byte return patch,
eighty-byte verifier, closed
receipts, exact WP8G ELF prefix, and fixed-le48-v1 expected result record.
Rocq reuses the complete WP8E target and checks the rewrite, jump destination,
verifier fields, failure edges, process extent, byte bounds, complete
fresh-process ELF envelope, and result-record decoding.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import s4_register_residency_candidate_authority as wp8e
import s4_register_residency_plan_authority as wp8c
import s4_register_residency_process as wp8g
import s4_register_residency_role as wp8h
import s4_register_residency_host as wp8i
import s4_residency_coq_certificate as semantic
import s4_residency_x86_coq_certificate as x86_bridge


class ProcessCertificateError(RuntimeError):
    """The admitted WP8E and WP8G artifacts cannot be joined exactly."""


@dataclass(frozen=True)
class ProcessKernel:
    ordinal: str
    ordinal_value: int
    name: str
    patch: tuple[int, ...]
    verifier: tuple[int, ...]
    elf_prefix: tuple[int, ...]
    result_record: tuple[int, ...]
    oracle: int
    process_bytes: int
    elf_bytes: int
    target_offset: int
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


@dataclass(frozen=True)
class ProcessReplayEvidence:
    report_root: str
    results: tuple[wp8g.ProcessResult, ...]


@dataclass(frozen=True)
class RoleReplayEvidence:
    report_root: str


@dataclass(frozen=True)
class HostBoundaryEvidence:
    report_root: str


def _signed_le32(raw: bytes, label: str) -> int:
    if len(raw) != 4:
        raise ProcessCertificateError(f"{label} is not four bytes")
    return int.from_bytes(raw, "little", signed=True)


def _le16(value: int) -> bytes:
    return value.to_bytes(2, "little", signed=False)


def _le32(value: int) -> bytes:
    return value.to_bytes(4, "little", signed=False)


def _le64(value: int) -> bytes:
    return value.to_bytes(8, "little", signed=False)


def _rel32(target: int, displacement: int) -> bytes:
    delta = target - (displacement + 4)
    if not -(1 << 31) <= delta < (1 << 31):
        raise ProcessCertificateError("WP8G process ELF rel32 escapes its bound")
    return delta.to_bytes(4, "little", signed=True)


def canonical_process_startup(ordinal: int, target_offset: int = 384) -> bytes:
    """Independently reconstruct the exact WP8G result-record startup."""

    if not 0 < ordinal < 65_536:
        raise ProcessCertificateError("WP8G process ELF ordinal escapes its bound")
    startup = bytearray(b"\xe8" + _rel32(target_offset, 257))
    startup += bytes.fromhex("4883ec3049b8") + b"NAUX5E01"
    startup += bytes.fromhex("4c89042449b8") + _le64(ordinal)
    startup += bytes.fromhex(
        "4c89442408"
        "4889442410"
        "48894c2418"
        "4889542420"
        "4889742428"
        "b801000000"
        "bf01000000"
        "4889e6"
        "ba30000000"
        "0f05"
        "4883f830"
    )
    failure_fixup = len(startup) + 2
    startup += bytes.fromhex("0f8500000000")
    startup += bytes.fromhex(
        "4883c430"
        "31ff"
        "b83c000000"
        "0f050f0b"
    )
    failure = len(startup)
    startup += bytes.fromhex("bf46000000b83c0000000f050f0b")
    startup[failure_fixup : failure_fixup + 4] = _rel32(
        failure, failure_fixup
    )
    if len(startup) != 117:
        raise ProcessCertificateError("WP8G process ELF startup extent drifted")
    return bytes(startup)


def canonical_process_elf_prefix(
    process: bytes, ordinal: int, target_offset: int = 384
) -> bytes:
    """Independently reconstruct the WP8G bytes preceding the process target."""

    if target_offset != 384:
        raise ProcessCertificateError("WP8G process ELF target offset drifted")
    image_bytes = target_offset + len(process)
    if image_bytes >= 65_536:
        raise ProcessCertificateError("WP8G process ELF exceeds the Rocq extent bound")
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
    prefix = bytearray(header + load + stack)
    prefix.extend(bytes(256 - len(prefix)))
    prefix.extend(canonical_process_startup(ordinal, target_offset))
    prefix.extend(bytes(target_offset - len(prefix)))
    if len(prefix) != target_offset:
        raise ProcessCertificateError("WP8G process ELF prefix extent drifted")
    return bytes(prefix)


def canonical_result_record(record: wp8g.ContractRecord) -> bytes:
    """Construct the exact fixed-le48-v1 success record for a kernel."""

    try:
        result = wp8g.RESULT_STRUCT.pack(
            wp8g.RESULT_MAGIC,
            record.ordinal,
            record.oracle,
            record.expected_outer,
            record.expected_inner,
            0,
        )
    except (OverflowError, ValueError, wp8g.struct.error) as error:
        raise ProcessCertificateError(
            "WP8G result field escapes the fixed-le48-v1 protocol"
        ) from error
    if len(result) != wp8g.RESULT_BYTES or len(result) != 48:
        raise ProcessCertificateError("WP8G result protocol extent drifted")
    return result


def parse_authenticated_replay_report(
    raw: bytes,
    admission: wp8g.Admission,
    candidate: wp8g.Candidate,
) -> ProcessReplayEvidence:
    """Authenticate the exact two-pass WP8G execution report."""

    try:
        lines = wp8g._canonical(raw, "WP8G replay report", wp8g.MAX_FILE_BYTES)
    except wp8g.ProcessReplayError as error:
        raise ProcessCertificateError(str(error)) from error
    records = admission.contract.records
    expected_lines = 10 + 2 * len(records)
    if len(lines) != expected_lines:
        raise ProcessCertificateError("WP8G replay report extent drifted")

    prefix = (
        wp8g.REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"candidate-report-sha256\t{wp8g.CANDIDATE_REPORT_SHA256}",
        "mode\tuntimed-fresh-process-replay",
        "replays\t2",
        "status\tfresh-process-checksum-work-parity-admitted",
        "claim-status\tuntimed-parity-only",
        "timing-status\tforbidden",
    )
    if tuple(lines[: len(prefix)]) != prefix:
        raise ProcessCertificateError("WP8G replay report metadata drifted")

    results: list[wp8g.ProcessResult] = []
    index = len(prefix)
    for pass_number in (1, 2):
        for record in records:
            expected = (
                "result",
                str(pass_number),
                f"{record.ordinal:02}",
                record.name,
                str(record.oracle),
                str(record.expected_outer),
                str(record.expected_inner),
                "0",
            )
            if tuple(lines[index].split("\t")) != expected:
                raise ProcessCertificateError(
                    "WP8G replay result identity or value drifted"
                )
            results.append(
                wp8g.ProcessResult(
                    pass_number,
                    record.ordinal,
                    record.name,
                    record.oracle,
                    record.expected_outer,
                    record.expected_inner,
                    0,
                )
            )
            index += 1

    result_tuple = tuple(results)
    expected_raw = wp8g._report(
        admission.contract,
        admission.authority,
        candidate,
        result_tuple,
    )
    if raw != expected_raw:
        raise ProcessCertificateError("WP8G replay report root drifted")
    marker = "report-root\t"
    if not lines[-1].startswith(marker):
        raise ProcessCertificateError("WP8G replay report root is missing")
    return ProcessReplayEvidence(lines[-1][len(marker) :], result_tuple)


def parse_authenticated_role_report(
    raw: bytes,
    admission: wp8h.Admission,
    process_report: bytes,
    process_evidence: ProcessReplayEvidence,
) -> RoleReplayEvidence:
    """Authenticate the WP8H role report against the exact WP8G replay."""

    try:
        lines = wp8h._canonical(raw, "WP8H role report")
    except wp8h.CandidateRoleError as error:
        raise ProcessCertificateError(str(error)) from error
    expected_lines = 19 + len(process_evidence.results)
    if len(lines) != expected_lines:
        raise ProcessCertificateError("WP8H role report extent drifted")

    prefix = (
        wp8h.REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"baseline-role-authority\t{wp8h.WP5F_AUTHORITY_SEAL}",
        f"license-transition-authority\t{wp8h.LT1_AUTHORITY_SEAL}",
        f"candidate-process-authority\t{wp8h.WP8G_AUTHORITY_SEAL}",
        "role-status\tuntimed-register-residency-candidate-admitted",
        "claim-status\tuntimed-candidate-role-only",
        "timing-status\tforbidden",
        "role\tnaux-register-residency-candidate",
        "baseline-role\tnaux-residual",
        "role-isolation\tdoes-not-replace-wp5f",
        "mode\tuntimed-candidate-role-replay",
        "kernels\t4",
        "replays\t2",
        "gates\t9",
        "closed-blockers\t1",
        f"process-report-root\t{process_evidence.report_root}",
    )
    if tuple(lines[: len(prefix)]) != prefix:
        raise ProcessCertificateError("WP8H role report metadata drifted")

    for index, result in enumerate(process_evidence.results, len(prefix)):
        expected = (
            "result",
            str(result.pass_number),
            f"{result.ordinal:02}",
            result.name,
            str(result.checksum),
            str(result.outer),
            str(result.inner),
            str(result.owner),
        )
        if tuple(lines[index].split("\t")) != expected:
            raise ProcessCertificateError(
                "WP8H role result identity or value drifted"
            )

    expected_raw = wp8h._report(
        admission.contract,
        admission.authority,
        process_evidence.results,
        process_report,
    )
    if raw != expected_raw:
        raise ProcessCertificateError("WP8H role report root drifted")
    marker = "report-root\t"
    if not lines[-1].startswith(marker):
        raise ProcessCertificateError("WP8H role report root is missing")
    return RoleReplayEvidence(lines[-1][len(marker) :])


def parse_authenticated_host_report(
    raw: bytes,
    admission: wp8i.Admission,
) -> HostBoundaryEvidence:
    """Authenticate the exact clock-free WP8I static boundary report."""

    try:
        lines = wp8i._canonical(raw, "WP8I static host report")
    except wp8i.CandidateHostError as error:
        raise ProcessCertificateError(str(error)) from error
    if len(lines) != 15:
        raise ProcessCertificateError("WP8I static host report extent drifted")

    prefix = (
        wp8i.REPORT_MAGIC,
        f"contract\t{admission.contract.seal}",
        f"authority\t{admission.authority.seal}",
        f"candidate-role-authority\t{wp8i.WP8H_AUTHORITY_SEAL}",
        f"host-protocol-authority\t{wp8i.WP6_AUTHORITY_SEAL}",
        "protocol-status\tcandidate-controlled-host-protocol-admitted",
        "host-status\tnot-observed",
        "role\tnaux-register-residency-candidate",
        "baseline-role\tnaux-residual",
        "claim-status\tnot-admitted",
        "timing-status\tforbidden",
        "mode\tstatic-authority",
        "gates\t9",
        "blockers\t3",
    )
    if tuple(lines[: len(prefix)]) != prefix:
        raise ProcessCertificateError("WP8I static host report metadata drifted")
    if raw != admission.static_report:
        raise ProcessCertificateError("WP8I static host report root drifted")
    marker = "report-root\t"
    if not lines[-1].startswith(marker):
        raise ProcessCertificateError("WP8I static host report root is missing")
    report_root = lines[-1][len(marker) :]
    if report_root != admission.static_root:
        raise ProcessCertificateError("WP8I static host report identity drifted")
    return HostBoundaryEvidence(report_root)


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
        elf = bytes(kernel.elf)
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
            record.startup_bytes != 117
            or record.target_offset != 384
            or record.elf_bytes != len(elf)
            or len(elf) != record.target_offset + len(process)
            or elf[record.target_offset :] != process
        ):
            raise ProcessCertificateError("WP8G process ELF receipt drifted")
        elf_prefix = elf[: record.target_offset]
        if elf_prefix != canonical_process_elf_prefix(
            process, record.ordinal, record.target_offset
        ):
            raise ProcessCertificateError("WP8G process ELF prefix drifted")
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
                ordinal_value=record.ordinal,
                name=record.name,
                patch=tuple(patch),
                verifier=tuple(verifier),
                elf_prefix=tuple(elf_prefix),
                result_record=tuple(canonical_result_record(record)),
                oracle=record.oracle,
                process_bytes=record.process_bytes,
                elf_bytes=record.elf_bytes,
                target_offset=record.target_offset,
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
    process_replay_root: str,
    role_replay_root: str,
    host_boundary_root: str,
) -> str:
    rows = [
        "(**",
        "  Generated from the sealed S4-WP8C through S4-WP8I artifacts.",
        f"  WP8C report root: {plan_root}",
        f"  WP8E report root: {encoding_root}",
        f"  WP8G candidate SHA-256: {process_report_sha256}",
        f"  WP8G authority report root: {process_authority_root}",
        f"  WP8G replay report root: {process_replay_root}",
        f"  WP8H role replay report root: {role_replay_root}",
        f"  WP8I static host report root: {host_boundary_root}",
        "  The generator is untrusted. Rocq receives only WP8G-owned patch and",
        "  verifier, ELF-prefix, and result-record bytes, reuses the checked",
        "  WP8E target, and validates the exact rewrite, complete process ELF",
        "  envelope, fixed-le48-v1 result decoding, and isolated untimed",
        "  candidate-role assignment while retaining the baseline role, then",
        "  binds that assignment to the static controlled-host protocol.",
        "  x86 execution, Linux loading, syscalls, timing, and performance",
        "  remain explicit non-claims.",
        "*)",
        "",
        "From Stdlib Require Import List ZArith Lia.",
        "From NauxCore Require Import X86ResidencyEncoding ResidencyProcessTarget",
        "  ELF64ResidencyEnvelope ELF64ResidencyProcessEnvelope",
        "  ResidencyResultProtocol ResidencyCandidateRole",
        "  ResidencyControlledHost",
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
                f"  change (length {prefix}_process =",
                f"    (length {wp8e_target} + 80)%nat).",
                "  exact (residency_process_target_extent",
                f"    {wp8e_target} {prefix}_patch {prefix}_verifier",
                f"    {prefix}_process {prefix}_receipt {prefix}_completion",
                f"    {prefix}_process_is_well_formed).",
                "Qed.",
                "",
                f"Theorem {prefix}_contains_verifier :",
                f"  skipn (length {wp8e_target}) {prefix}_process =",
                f"    {prefix}_verifier.",
                "Proof.",
                "  exact (residency_process_target_contains_verifier",
                f"    {wp8e_target} {prefix}_patch {prefix}_verifier",
                f"    {prefix}_process {prefix}_receipt {prefix}_completion",
                f"    {prefix}_process_is_well_formed).",
                "Qed.",
                "",
                f"Theorem {prefix}_process_bytes_are_bounded :",
                f"  Forall (fun byte => (byte < 256)%nat) {prefix}_process.",
                "Proof.",
                "  exact (residency_process_target_bytes_are_bounded",
                f"    {wp8e_target} {prefix}_patch {prefix}_verifier",
                f"    {prefix}_process {prefix}_receipt {prefix}_completion",
                f"    wp8e_kernel_{kernel.ordinal}_target_bytes_are_bounded",
                f"    {prefix}_process_is_well_formed).",
                "Qed.",
                "",
                f"Definition {prefix}_reported_elf_prefix : list nat :=",
                f"  {_coq_list(kernel.elf_prefix)}.",
                "",
                f"Definition {prefix}_elf_image : list nat :=",
                f"  {prefix}_reported_elf_prefix ++ {prefix}_process.",
                "",
                f"Example {prefix}_reported_elf_prefix_extent :",
                f"  length {prefix}_reported_elf_prefix =",
                f"    {_coq_nat(kernel.target_offset)}.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Example {prefix}_reported_elf_prefix_is_canonical :",
                f"  {prefix}_reported_elf_prefix =",
                "    elf64_residency_process_prefix",
                f"      {prefix}_process {_coq_nat(kernel.ordinal_value)}.",
                "Proof.",
                "  unfold elf64_residency_process_prefix,",
                "    elf64_residency_process_image_bytes.",
                f"  rewrite {prefix}_process_extent.",
                "  vm_compute. reflexivity.",
                "Qed.",
                "",
                f"Example {prefix}_elf_extent_fits :",
                "  elf64_residency_process_extent_fitsb",
                f"    {prefix}_process = true.",
                "Proof.",
                "  unfold elf64_residency_process_extent_fitsb,",
                "    elf64_residency_process_image_bytes.",
                f"  rewrite {prefix}_process_extent.",
                "  vm_compute. reflexivity.",
                "Qed.",
                "",
                f"Example {prefix}_elf_ordinal_is_valid :",
                "  elf64_residency_process_ordinal_validb",
                f"    {_coq_nat(kernel.ordinal_value)} = true.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Example {prefix}_reported_elf_prefix_bytes_check :",
                "  forallb elf64_residency_byte_validb",
                f"    {prefix}_reported_elf_prefix = true.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Theorem {prefix}_reported_elf_prefix_bytes_are_bounded :",
                "  Forall (fun byte => (byte < 256)%nat)",
                f"    {prefix}_reported_elf_prefix.",
                "Proof.",
                "  apply elf64_residency_bytes_check_sound.",
                f"  exact {prefix}_reported_elf_prefix_bytes_check.",
                "Qed.",
                "",
                f"Theorem {prefix}_elf_image_is_well_formed :",
                "  elf64_residency_process_image_well_formed",
                f"    {prefix}_process {_coq_nat(kernel.ordinal_value)}",
                f"    {prefix}_elf_image.",
                "Proof.",
                f"  unfold {prefix}_elf_image.",
                "  apply elf64_residency_process_image_from_prefix.",
                f"  - exact {prefix}_reported_elf_prefix_bytes_are_bounded.",
                f"  - exact {prefix}_process_bytes_are_bounded.",
                f"  - exact {prefix}_elf_extent_fits.",
                f"  - exact {prefix}_elf_ordinal_is_valid.",
                f"  - exact {prefix}_reported_elf_prefix_is_canonical.",
                "Qed.",
                "",
                f"Corollary {prefix}_elf_image_extent :",
                f"  length {prefix}_elf_image = {_coq_nat(kernel.elf_bytes)}.",
                "Proof.",
                f"  unfold {prefix}_elf_image. rewrite length_app.",
                f"  rewrite {prefix}_reported_elf_prefix_extent,",
                f"    {prefix}_process_extent.",
                "  reflexivity.",
                "Qed.",
                "",
                f"Corollary {prefix}_elf_contains_process :",
                f"  skipn {_coq_nat(kernel.target_offset)} {prefix}_elf_image =",
                f"    {prefix}_process.",
                "Proof.",
                "  exact (elf64_residency_process_well_formed_contains_target",
                f"    {prefix}_process {_coq_nat(kernel.ordinal_value)}",
                f"    {prefix}_elf_image {prefix}_elf_image_is_well_formed).",
                "Qed.",
                "",
                f"Definition {prefix}_expected_result : residency_result_record :=",
                "  {| residency_result_ordinal := "
                f"{_coq_z(kernel.ordinal_value)};",
                "     residency_result_checksum := "
                f"{_coq_z(kernel.oracle)};",
                "     residency_result_outer := "
                f"{_coq_z(kernel.expected_outer)};",
                "     residency_result_inner := "
                f"{_coq_z(kernel.expected_inner)};",
                "     residency_result_owner := 0%Z |}.",
                "",
                f"Definition {prefix}_expected_result_bytes : list nat :=",
                f"  {_coq_list(kernel.result_record)}.",
                "",
                f"Example {prefix}_expected_result_protocol_decodes :",
                f"  residency_result_decode {prefix}_expected_result_bytes =",
                f"    Some {prefix}_expected_result.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Example {prefix}_expected_result_protocol_extent :",
                f"  length {prefix}_expected_result_bytes = residency_result_bytes.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Theorem {prefix}_expected_result_protocol_is_well_formed :",
                "  residency_result_record_well_formed",
                f"    {prefix}_expected_result_bytes.",
                "Proof.",
                "  destruct (residency_result_decode_sound",
                f"    {prefix}_expected_result_bytes {prefix}_expected_result",
                f"    {prefix}_expected_result_protocol_decodes) as [Hshape _].",
                "  exact Hshape.",
                "Qed.",
                "",
                f"Definition {prefix}_role_assignment :",
                "    residency_role_assignment :=",
                "  {| residency_assignment_role :=",
                "       ResidencyRegisterCandidateRole;",
                "     residency_assignment_timing := ResidencyTimingForbidden;",
                "     residency_assignment_baseline_retained := true;",
                "     residency_assignment_ordinal := "
                f"{_coq_nat(kernel.ordinal_value)};",
                f"     residency_assignment_process := {prefix}_process;",
                f"     residency_assignment_elf := {prefix}_elf_image;",
                "     residency_assignment_result_bytes :=",
                f"       {prefix}_expected_result_bytes;",
                "     residency_assignment_expected_result :=",
                f"       {prefix}_expected_result |}}.",
                "",
                f"Theorem {prefix}_candidate_role_is_admitted :",
                "  residency_candidate_role_admitted",
                f"    {prefix}_role_assignment.",
                "Proof.",
                "  unfold residency_candidate_role_admitted,",
                f"    {prefix}_role_assignment.",
                "  split; [reflexivity |].",
                "  split; [reflexivity |].",
                "  split; [reflexivity |].",
                "  split.",
                "  - vm_compute. lia.",
                "  - split; [reflexivity |].",
                "    split.",
                f"    + exact {prefix}_expected_result_protocol_decodes.",
                f"    + exact {prefix}_elf_contains_process.",
                "Qed.",
                "",
                f"Corollary {prefix}_candidate_role_is_isolated :",
                f"  residency_assignment_role {prefix}_role_assignment <>",
                "    ResidencyBaselineRole.",
                "Proof.",
                "  exact (residency_candidate_role_is_not_baseline",
                f"    {prefix}_role_assignment {prefix}_candidate_role_is_admitted).",
                "Qed.",
                "",
                f"Corollary {prefix}_candidate_role_is_untimed :",
                f"  residency_assignment_timing {prefix}_role_assignment =",
                "    ResidencyTimingForbidden.",
                "Proof.",
                "  exact (residency_candidate_role_has_no_timing_authority",
                f"    {prefix}_role_assignment {prefix}_candidate_role_is_admitted).",
                "Qed.",
                "",
                f"Corollary {prefix}_candidate_role_retains_baseline :",
                "  residency_assignment_baseline_retained",
                f"    {prefix}_role_assignment = true.",
                "Proof.",
                "  exact (residency_candidate_role_retains_baseline",
                f"    {prefix}_role_assignment {prefix}_candidate_role_is_admitted).",
                "Qed.",
                "",
                f"Definition {prefix}_controlled_host_binding :",
                "    residency_controlled_host_binding :=",
                "  {| residency_host_candidate :=",
                f"       {prefix}_role_assignment;",
                "     residency_host_protocol_linked := true;",
                "     residency_host_observation_state :=",
                "       ResidencyHostNotObserved;",
                "     residency_host_timing := ResidencyTimingForbidden;",
                "     residency_host_performance_claim :=",
                "       ResidencyPerformanceClaimForbidden |}.",
                "",
                f"Theorem {prefix}_static_host_boundary_is_admitted :",
                "  residency_static_host_boundary_admitted",
                f"    {prefix}_controlled_host_binding.",
                "Proof.",
                "  unfold residency_static_host_boundary_admitted,",
                f"    {prefix}_controlled_host_binding.",
                "  split.",
                f"  - exact {prefix}_candidate_role_is_admitted.",
                "  - split; [reflexivity |].",
                "    split; [reflexivity |].",
                "    split; reflexivity.",
                "Qed.",
                "",
                f"Corollary {prefix}_static_host_has_no_observation :",
                "  residency_host_observation_state",
                f"    {prefix}_controlled_host_binding = ResidencyHostNotObserved.",
                "Proof.",
                "  exact (residency_static_host_boundary_has_no_observation",
                f"    {prefix}_controlled_host_binding",
                f"    {prefix}_static_host_boundary_is_admitted).",
                "Qed.",
                "",
                f"Corollary {prefix}_static_host_is_not_measurement_ready :",
                "  ~ residency_candidate_measurement_ready",
                f"      {prefix}_controlled_host_binding.",
                "Proof.",
                "  exact (residency_static_host_boundary_is_not_measurement_ready",
                f"    {prefix}_controlled_host_binding",
                f"    {prefix}_static_host_boundary_is_admitted).",
                "Qed.",
                "",
                f"Corollary {prefix}_static_host_has_no_performance_claim :",
                "  residency_host_performance_claim",
                f"    {prefix}_controlled_host_binding =",
                "      ResidencyPerformanceClaimForbidden.",
                "Proof.",
                "  exact (residency_static_host_boundary_has_no_performance_claim",
                f"    {prefix}_controlled_host_binding",
                f"    {prefix}_static_host_boundary_is_admitted).",
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
    parser.add_argument("--replay-report", required=True, type=Path)
    parser.add_argument("--role-report", required=True, type=Path)
    parser.add_argument("--host-report", required=True, type=Path)
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
        role_admission = wp8h.validate(root)
        host_admission = wp8i.validate(root)
        if (
            host_admission.candidate.contract.seal
            != role_admission.contract.seal
            or host_admission.candidate.authority.seal
            != role_admission.authority.seal
        ):
            raise ProcessCertificateError("WP8H/WP8I candidate role identity drifted")

        plan_raw = arguments.plan_report.read_bytes()
        encoding_raw = arguments.encoding_report.read_bytes()
        process_raw = arguments.process_report.read_bytes()
        replay_raw = arguments.replay_report.read_bytes()
        role_raw = arguments.role_report.read_bytes()
        host_raw = arguments.host_report.read_bytes()
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
        replay_evidence = parse_authenticated_replay_report(
            replay_raw, process_admission, process_candidate
        )
        role_evidence = parse_authenticated_role_report(
            role_raw, role_admission, replay_raw, replay_evidence
        )
        host_evidence = parse_authenticated_host_report(
            host_raw, host_admission
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
            replay_evidence.report_root,
            role_evidence.report_root,
            host_evidence.report_root,
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
        wp8h.CandidateRoleError,
        wp8i.CandidateHostError,
        wp8i.wp6.HostControlError,
        OSError,
        ValueError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
