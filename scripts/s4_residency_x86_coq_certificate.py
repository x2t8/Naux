#!/usr/bin/env python3
"""Bind admitted WP8C residency sites to admitted WP8E x86-64 bytes in Rocq.

The translator is intentionally untrusted.  It authenticates both source
reports with their sealed authorities, copies the complete candidate target
bytes into Rocq, and emits only closed site/ABI records.  Rocq then checks that
the site list exactly covers the WP8C control graph and that every referenced
byte range decodes as the required seven-byte r12 template.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re

import s4_register_residency_candidate_authority as wp8e
import s4_register_residency_plan_authority as wp8c
import s4_residency_coq_certificate as semantic


class X86CertificateError(RuntimeError):
    """The admitted reports cannot be joined by the closed Rocq model."""


LOAD_RE = re.compile(
    r"OwnershipPlain \(HeapScalarInstruction \(ResidencyAccess "
    r"\(LoadHome ([0-9]+)%nat\)\)\)\Z"
)
STORE_RE = re.compile(r"OwnershipStoreHome ([0-9]+)%nat (true|false)\Z")


@dataclass(frozen=True)
class NativeSite:
    block: int
    ordinal: int
    start: int
    semantics: str


@dataclass(frozen=True)
class NativeKernel:
    ordinal: str
    name: str
    target: tuple[int, ...]
    target_bytes: int
    error_offset: int
    save_start: int
    shadow_displacement: int
    sites: tuple[NativeSite, ...]
    restore_starts: tuple[int, ...]


def _unsigned(raw: str, label: str) -> int:
    if not raw or not raw.isascii() or not raw.isdigit():
        raise X86CertificateError(f"{label} is not an unsigned integer")
    if raw != "0" and raw.startswith("0"):
        raise X86CertificateError(f"{label} is not canonical")
    return int(raw)


def _semantic_site(action: str) -> str | None:
    load = LOAD_RE.fullmatch(action)
    if load is not None:
        return f"X86SemanticLoadPhysical {int(load.group(1))}%nat"
    store = STORE_RE.fullmatch(action)
    if store is not None:
        return (
            f"X86SemanticStorePhysical {int(store.group(1))}%nat "
            f"{store.group(2)}"
        )
    return None


def _expected_semantic_sites(
    kernel: semantic.Kernel,
) -> tuple[tuple[int, int, str], ...]:
    sites: list[tuple[int, int, str]] = []
    for block in kernel.blocks:
        for ordinal, action in enumerate(block.ownership_actions):
            encoded = _semantic_site(action)
            if encoded is not None:
                sites.append((block.block_id, ordinal, encoded))
    return tuple(sites)


def _decode_template(raw: bytes) -> tuple[str, int]:
    if len(raw) != 7 or raw[:3] not in {b"\x4c\x89\xa5", b"\x4c\x8b\xa5"}:
        raise X86CertificateError("candidate site is not an admitted seven-byte template")
    displacement = int.from_bytes(raw[3:], "little", signed=True)
    kind = "store-r12" if raw[1] == 0x89 else "load-r12"
    return kind, displacement


def _canonical_lines(raw: bytes, label: str) -> list[str]:
    if not raw or not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise X86CertificateError(f"{label} has invalid extent or encoding")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise X86CertificateError(f"{label} is not UTF-8") from error
    if any(not line or line != line.strip() for line in lines):
        raise X86CertificateError(f"{label} contains blank or padded rows")
    return lines


def parse_joined_reports(
    plan_raw: bytes,
    encoding_raw: bytes,
    plan_kernels: list[semantic.Kernel],
    wp8d_kernels: tuple[tuple[str, ...], ...],
) -> list[NativeKernel]:
    # Parsing plan_raw again here ensures the caller cannot pair a parsed plan
    # object with different report bytes.
    reparsed = semantic.parse_verified_report(plan_raw)
    if reparsed != plan_kernels:
        raise X86CertificateError("parsed WP8C plan object does not match report bytes")

    lines = _canonical_lines(encoding_raw, "WP8E report")
    if lines[0] != wp8e.CANDIDATE_MAGIC:
        raise X86CertificateError("WP8E report magic drifted")
    plan_by_ordinal = {kernel.ordinal: kernel for kernel in plan_kernels}
    displacement_by_ordinal = {
        row[0]: int(row[7]) for row in wp8d_kernels
    }

    index = 1
    while index < len(lines) and lines[index].startswith("meta\t"):
        index += 1
    kernels: list[NativeKernel] = []
    while index < len(lines) and lines[index].startswith("kernel\t"):
        kernel_fields = lines[index].split("\t")
        index += 1
        if len(kernel_fields) != 10:
            raise X86CertificateError("WP8E kernel row is malformed")
        ordinal, name = kernel_fields[1], kernel_fields[2]
        plan = plan_by_ordinal.get(ordinal)
        if plan is None or plan.name != name:
            raise X86CertificateError("WP8C/WP8E kernel identity drifted")
        target_bytes = _unsigned(kernel_fields[6], "candidate target bytes")
        error_offset = _unsigned(kernel_fields[7], "candidate error offset")
        declared_sites = _unsigned(kernel_fields[8], "transformed site count")
        declared_returns = _unsigned(kernel_fields[9], "return count")

        abi_fields = lines[index].split("\t")
        index += 1
        if (
            len(abi_fields) != 6
            or abi_fields[:3] != ["abi", ordinal, "save-r12"]
            or abi_fields[5] != "restore-every-return"
        ):
            raise X86CertificateError("WP8E ABI row is malformed")
        save_start = _unsigned(abi_fields[3], "ABI save start")
        save_end = _unsigned(abi_fields[4], "ABI save end")
        if save_end - save_start != 7:
            raise X86CertificateError("WP8E ABI save width drifted")

        site_rows: list[tuple[int, int, str, int, int]] = []
        restore_starts: list[int] = []
        while index < len(lines) and lines[index].startswith(f"range\t{ordinal}\t"):
            fields = lines[index].split("\t")
            index += 1
            if len(fields) != 9:
                raise X86CertificateError("WP8E range row is malformed")
            block = _unsigned(fields[2], "range block")
            operation = _unsigned(fields[3], "range ordinal")
            kind = fields[4]
            start = _unsigned(fields[5], "range start")
            end = _unsigned(fields[6], "range end")
            if kind in {"load-physical", "store-physical"}:
                site_rows.append((block, operation, kind, start, end))
            elif kind == "return-with-restore":
                restore_starts.append(start)

        target_fields = lines[index].split("\t")
        index += 1
        if len(target_fields) != 3 or target_fields[:2] != ["target-hex", ordinal]:
            raise X86CertificateError("WP8E target row is malformed")
        try:
            target = bytes.fromhex(target_fields[2])
        except ValueError as error:
            raise X86CertificateError("WP8E target hex is malformed") from error
        if len(target) != target_bytes or error_offset > len(target):
            raise X86CertificateError("WP8E target extent drifted")

        shadow = displacement_by_ordinal.get(ordinal)
        if shadow is None:
            raise X86CertificateError("WP8D shadow displacement is absent")
        save_kind, save_displacement = _decode_template(target[save_start:save_end])
        if (save_kind, save_displacement) != ("store-r12", shadow):
            raise X86CertificateError("WP8E save template does not match WP8D shadow")

        sites: list[NativeSite] = []
        for block, operation, kind, start, end in site_rows:
            if block >= len(plan.blocks) or operation >= len(
                plan.blocks[block].ownership_actions
            ):
                raise X86CertificateError("WP8E site points outside the WP8C graph")
            semantics = _semantic_site(plan.blocks[block].ownership_actions[operation])
            if semantics is None:
                raise X86CertificateError("WP8E transformed range maps to a plain WP8C site")
            template_kind, _ = _decode_template(target[start:end])
            expected_kind = "store-r12" if kind == "load-physical" else "load-r12"
            if template_kind != expected_kind:
                raise X86CertificateError("WP8E template direction contradicts WP8C semantics")
            sites.append(NativeSite(block, operation, start, semantics))

        for restore_start in restore_starts:
            restore_kind, restore_displacement = _decode_template(
                target[restore_start : restore_start + 7]
            )
            if (restore_kind, restore_displacement) != ("load-r12", shadow):
                raise X86CertificateError("WP8E restore template does not match ABI save")

        actual_locations = tuple(
            (site.block, site.ordinal, site.semantics) for site in sites
        )
        if actual_locations != _expected_semantic_sites(plan):
            raise X86CertificateError("WP8E sites do not exactly cover WP8C residency sites")
        return_count = sum(
            block.control_terminator is not None
            and block.control_terminator.startswith("OwnershipControlReturn")
            for block in plan.blocks
        )
        if len(sites) != declared_sites or len(restore_starts) != declared_returns:
            raise X86CertificateError("WP8E site or return cardinality drifted")
        if declared_returns != return_count:
            raise X86CertificateError("WP8E restores do not cover every WP8C return")
        kernels.append(
            NativeKernel(
                ordinal=ordinal,
                name=name,
                target=tuple(target),
                target_bytes=target_bytes,
                error_offset=error_offset,
                save_start=save_start,
                shadow_displacement=shadow,
                sites=tuple(sites),
                restore_starts=tuple(restore_starts),
            )
        )

    if len(kernels) != len(plan_kernels):
        raise X86CertificateError("WP8E kernel extent does not match WP8C")
    if lines[index : index + 2] != [
        "verification\tindependent-byte-parser-accepted",
        "verification\tno-elf-no-execution-no-measurement",
    ]:
        raise X86CertificateError("WP8E verification surface drifted")
    if index + 3 != len(lines) or not lines[index + 2].startswith("report-root\t"):
        raise X86CertificateError("WP8E report tail drifted")
    return kernels


def _coq_nat(value: int) -> str:
    return f"{value}%nat"


def _coq_z(value: int) -> str:
    return f"({value}%Z)" if value < 0 else f"{value}%Z"


def _coq_list(values: list[str]) -> str:
    return "[" + "; ".join(values) + "]"


def emit_rocq(
    kernels: list[NativeKernel], plan_root: str, encoding_root: str
) -> str:
    rows = [
        "(**",
        "  Generated from the sealed S4-WP8C semantic plan and S4-WP8E",
        "  candidate function-byte report.",
        f"  WP8C report root: {plan_root}",
        f"  WP8E report root: {encoding_root}",
        "  The generator is untrusted. Rocq receives each complete target byte",
        "  list, checks every transformed site against the WP8C control graph,",
        "  and decodes the r12 save/load templates at their exact offsets.",
        "  Passthrough bytes, rel32 relocation, full x86 semantics, ELF loading,",
        "  and native execution remain explicit non-claims.",
        "*)",
        "",
        "From Stdlib Require Import List ZArith.",
        "From NauxCore Require Import ControlFlowMachineIRResidency",
        "  X86ResidencyEncoding GeneratedWP8CCertificates.",
        "Import ListNotations.",
        "",
    ]
    for kernel in kernels:
        prefix = f"wp8e_kernel_{kernel.ordinal}"
        target = _coq_list([_coq_nat(byte) for byte in kernel.target])
        sites = []
        for site in kernel.sites:
            sites.append(
                "{| x86_residency_encoded_location := "
                "{| x86_residency_block := "
                f"{_coq_nat(site.block)}; x86_residency_ordinal := "
                f"{_coq_nat(site.ordinal)}; x86_residency_semantics := "
                f"{site.semantics} |}}; x86_residency_encoded_start := "
                f"{_coq_nat(site.start)} |}}"
            )
        restores = _coq_list(
            [_coq_nat(start) for start in kernel.restore_starts]
        )
        rows.extend(
            [
                f"(** {kernel.name}; complete candidate function bytes. *)",
                f"Definition {prefix}_target : list nat := {target}.",
                "",
                f"Definition {prefix}_sites : list x86_residency_encoded_site :=",
                f"  {_coq_list(sites)}.",
                "",
                f"Definition {prefix}_abi : x86_residency_abi :=",
                "  {| x86_residency_shadow_displacement := "
                f"{_coq_z(kernel.shadow_displacement)};",
                f"     x86_residency_save_start := {_coq_nat(kernel.save_start)};",
                f"     x86_residency_restore_starts := {restores} |}}.",
                "",
                f"Definition {prefix}_native_certificate :",
                "    x86_residency_native_certificate :=",
                f"  {{| x86_residency_target_bytes := {prefix}_target;",
                f"     x86_residency_encoded_sites := {prefix}_sites;",
                f"     x86_residency_abi_evidence := {prefix}_abi |}}.",
                "",
                f"Example {prefix}_target_extent :",
                f"  length {prefix}_target = {_coq_nat(kernel.target_bytes)}.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Example {prefix}_target_bytes_check :",
                f"  forallb x86_byte_validb {prefix}_target = true.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Theorem {prefix}_target_bytes_are_bounded :",
                f"  Forall (fun byte => byte < 256) {prefix}_target.",
                "Proof.",
                "  apply x86_bytes_check_sound.",
                f"  exact {prefix}_target_bytes_check.",
                "Qed.",
                "",
                f"Definition {prefix}_error_offset : nat :=",
                f"  {_coq_nat(kernel.error_offset)}.",
                "",
                f"Example {prefix}_native_certificate_checks :",
                "  x86_residency_native_certificate_check",
                f"    {prefix}_native_certificate = true.",
                "Proof. vm_compute. reflexivity. Qed.",
                "",
                f"Example {prefix}_sites_cover_wp8c_graph :",
                "  map x86_residency_encoded_location",
                f"      {prefix}_sites =",
                "    x86_residency_graph_sites",
                f"      wp8c_kernel_{kernel.ordinal}_control_graph.",
                "Proof. reflexivity. Qed.",
                "",
                f"Example {prefix}_restores_cover_wp8c_returns :",
                f"  length (x86_residency_restore_starts {prefix}_abi) =",
                "    x86_residency_return_count",
                "      (ownership_control_blocks",
                f"        wp8c_kernel_{kernel.ordinal}_control_graph).",
                "Proof. reflexivity. Qed.",
                "",
                f"Theorem {prefix}_function_bytes_cover_residency_graph :",
                "  x86_residency_certificate_covers_graph",
                f"    wp8c_kernel_{kernel.ordinal}_control_graph",
                f"    {prefix}_native_certificate.",
                "Proof.",
                "  apply x86_residency_checked_certificate_covers_graph.",
                "  - vm_compute. reflexivity.",
                "  - reflexivity.",
                "  - reflexivity.",
                "Qed.",
                "",
            ]
        )
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-report", required=True, type=Path)
    parser.add_argument("--encoding-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    arguments = parser.parse_args()
    try:
        root = arguments.repo_root.resolve(strict=True)
        plan_admission = wp8c.validate(root, arguments.plan_report)
        encoding_authority, encoding_admission, _, _ = wp8e.validate(
            root, arguments.encoding_report
        )
        del encoding_authority
        plan_raw = arguments.plan_report.read_bytes()
        encoding_raw = arguments.encoding_report.read_bytes()
        plan_kernels = semantic.parse_verified_report(plan_raw)
        wp8d_admission = wp8e.wp8d.validate(root)
        kernels = parse_joined_reports(
            plan_raw,
            encoding_raw,
            plan_kernels,
            wp8d_admission.contract.kernels,
        )
        output = emit_rocq(
            kernels, plan_admission.plan.root, encoding_admission.root
        )
        arguments.output.write_text(output, encoding="utf-8", newline="\n")
    except (
        X86CertificateError,
        semantic.CertificateError,
        wp8c.PlanAuthorityError,
        wp8e.CandidateAuthorityError,
        wp8e.wp8d.EncodingContractError,
        OSError,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
