#!/usr/bin/env python3
"""Translate an admitted WP8C report into Rocq initialization certificates.

The Python translation is not trusted for the theorem.  It first replays the
existing sealed WP8C authority, emits only fixed Rocq constructors and numeric
block identifiers, and leaves admission to DefiniteInitialization.v's
executable checker inside the Rocq kernel.
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import s4_register_residency_plan_authority as authority


class CertificateError(RuntimeError):
    """The admitted report cannot be represented by the bounded Rocq model."""


@dataclass
class Block:
    block_id: int
    declared_instructions: int
    actions: list[str] = field(default_factory=list)
    raw_instruction_count: int = 0
    successors: list[int] | None = None


@dataclass
class Kernel:
    ordinal: str
    name: str
    declared_blocks: int
    blocks: list[Block] = field(default_factory=list)


def _unsigned(raw: str, label: str) -> int:
    if not raw or (raw != "0" and raw.startswith("0")) or not raw.isascii() or not raw.isdigit():
        raise CertificateError(f"{label} is not a canonical unsigned integer")
    return int(raw)


def _target(raw: str, label: str) -> int:
    if not raw.startswith("b"):
        raise CertificateError(f"{label} is not a canonical block target")
    return _unsigned(raw[1:], label)


def _physical_action(parts: list[str]) -> str | None:
    opcode = parts[4]
    if opcode == "store-physical":
        if len(parts) != 8 or parts[5] != "r12":
            raise CertificateError("store-physical is outside the one-hot r12 model")
        return "StoreHome 0"
    if opcode == "load-physical":
        if len(parts) != 7 or parts[6] != "r12":
            raise CertificateError("load-physical is outside the one-hot r12 model")
        return "LoadHome 0"
    if opcode == "add-physical-const":
        if len(parts) != 7 or parts[5] != "r12":
            raise CertificateError("add-physical-const is outside the one-hot r12 model")
        return "UpdateHome (AddConst 0)"
    if "physical" in opcode:
        raise CertificateError(f"unsupported physical instruction {opcode!r}")
    return None


def _successors(parts: list[str]) -> list[int]:
    opcode = parts[3]
    if opcode == "goto" and len(parts) == 5:
        return [_target(parts[4], "goto target")]
    if opcode == "branch" and len(parts) == 7:
        return [
            _target(parts[5], "true target"),
            _target(parts[6], "false target"),
        ]
    if opcode == "return" and len(parts) == 5:
        return []
    raise CertificateError(f"unsupported or malformed terminator {opcode!r}")


def parse_verified_report(raw: bytes) -> list[Kernel]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CertificateError("verified report is not UTF-8") from error

    kernels: list[Kernel] = []
    current_kernel: Kernel | None = None
    current_block: Block | None = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        parts = line.split("\t")
        row = parts[0]
        if row == "kernel":
            if current_block is not None:
                raise CertificateError(f"line {line_number}: prior block lacks a terminator")
            if len(parts) != 12:
                raise CertificateError(f"line {line_number}: malformed kernel row")
            ordinal = parts[1]
            if ordinal != f"{len(kernels) + 1:02d}":
                raise CertificateError(f"line {line_number}: non-canonical kernel ordinal")
            current_kernel = Kernel(
                ordinal=ordinal,
                name=parts[2],
                declared_blocks=_unsigned(parts[11], "kernel block count"),
            )
            kernels.append(current_kernel)
        elif row == "block":
            if current_kernel is None or current_block is not None or len(parts) != 4:
                raise CertificateError(f"line {line_number}: malformed block boundary")
            if parts[1] != current_kernel.ordinal:
                raise CertificateError(f"line {line_number}: block belongs to another kernel")
            block_id = _unsigned(parts[2], "block id")
            if block_id != len(current_kernel.blocks):
                raise CertificateError(f"line {line_number}: block ids are not contiguous")
            current_block = Block(
                block_id=block_id,
                declared_instructions=_unsigned(parts[3], "instruction count"),
            )
        elif row == "instruction":
            if current_kernel is None or current_block is None or len(parts) < 5:
                raise CertificateError(f"line {line_number}: instruction is outside a block")
            if parts[1] != current_kernel.ordinal:
                raise CertificateError(f"line {line_number}: instruction belongs to another kernel")
            if _unsigned(parts[2], "instruction block") != current_block.block_id:
                raise CertificateError(f"line {line_number}: instruction block drifted")
            instruction_id = _unsigned(parts[3], "instruction id")
            if instruction_id != current_block.raw_instruction_count:
                raise CertificateError(f"line {line_number}: instruction ids are not contiguous")
            current_block.raw_instruction_count += 1
            action = _physical_action(parts)
            if action is not None:
                current_block.actions.append(action)
        elif row == "terminator":
            if current_kernel is None or current_block is None or len(parts) < 4:
                raise CertificateError(f"line {line_number}: terminator is outside a block")
            if parts[1] != current_kernel.ordinal:
                raise CertificateError(f"line {line_number}: terminator belongs to another kernel")
            if _unsigned(parts[2], "terminator block") != current_block.block_id:
                raise CertificateError(f"line {line_number}: terminator block drifted")
            if current_block.raw_instruction_count != current_block.declared_instructions:
                raise CertificateError(f"line {line_number}: instruction extent drifted")
            current_block.successors = _successors(parts)
            current_kernel.blocks.append(current_block)
            current_block = None
        elif row in {
            "NAUX-S4-REGISTER-RESIDENCY-PLAN",
            "meta",
            "abi",
            "replay",
            "verification",
            "report-root",
        }:
            continue
        else:
            raise CertificateError(f"line {line_number}: unknown report row {row!r}")

    if current_block is not None:
        raise CertificateError("final block lacks a terminator")
    if not kernels:
        raise CertificateError("verified report contains no kernels")
    for kernel in kernels:
        if len(kernel.blocks) != kernel.declared_blocks:
            raise CertificateError(f"kernel {kernel.ordinal} block extent drifted")
        for block in kernel.blocks:
            if block.successors is None:
                raise CertificateError(
                    f"kernel {kernel.ordinal} block b{block.block_id} lacks a terminator"
                )
            if any(successor >= len(kernel.blocks) for successor in block.successors):
                raise CertificateError(
                    f"kernel {kernel.ordinal} targets a missing block"
                )
    return kernels


def derive_must_facts(kernel: Kernel) -> tuple[list[bool], list[bool]]:
    """Replay the monotone must analysis used by the Rust WP8C verifier."""

    incoming: list[bool | None] = [None] * len(kernel.blocks)
    incoming[0] = False
    worklist: deque[int] = deque([0])
    while worklist:
        block_id = worklist.popleft()
        initialized = incoming[block_id]
        if initialized is None:
            raise CertificateError("worklist lost its incoming must fact")
        block = kernel.blocks[block_id]
        for action in block.actions:
            if action.startswith("StoreHome"):
                initialized = True
            elif not initialized:
                raise CertificateError(
                    f"kernel {kernel.ordinal} block b{block_id} reads r12 before initialization"
                )
        if block.successors is None:
            raise CertificateError(
                f"kernel {kernel.ordinal} block b{block_id} lacks a terminator"
            )
        for successor in block.successors:
            current = incoming[successor]
            merged = initialized if current is None else current and initialized
            if current != merged:
                incoming[successor] = merged
                worklist.append(successor)

    reachable = [fact is not None for fact in incoming]
    conservative = [False if fact is None else fact for fact in incoming]
    return reachable, conservative


def _coq_bool(value: bool) -> str:
    return "true" if value else "false"


def _coq_list(values: list[str]) -> str:
    return "[" + "; ".join(values) + "]"


def emit_rocq(kernels: list[Kernel], report_root: str) -> str:
    rows = [
        "(**",
        "  Generated from the sealed S4-WP8C candidate-plan report.",
        f"  Report root: {report_root}",
        "  The translation is untrusted; every certificate is admitted again",
        "  by NauxCore.DefiniteInitialization inside the Rocq kernel.",
        "*)",
        "",
        "From Stdlib Require Import List.",
        "From NauxCore Require Import RegisterResidency DefiniteInitialization.",
        "Import ListNotations.",
        "",
    ]
    for kernel in kernels:
        reachable, incoming = derive_must_facts(kernel)
        prefix = f"wp8c_kernel_{kernel.ordinal}"
        block_rows = [_coq_list(block.actions) for block in kernel.blocks]
        successor_rows = [
            _coq_list([str(value) for value in block.successors or []])
            for block in kernel.blocks
        ]
        rows.extend(
            [
                f"Definition {prefix}_graph : initialization_graph :=",
                "  {| initialization_entry := 0;",
                f"     initialization_blocks := {_coq_list(block_rows)};",
                f"     initialization_successors := {_coq_list(successor_rows)} |}}.",
                "",
                f"Definition {prefix}_certificate : cfg_initialization_certificate :=",
                f"  {{| initialization_cfg := {prefix}_graph;",
                "     initialization_reachable := "
                f"{_coq_list([_coq_bool(value) for value in reachable])};",
                "     initialization_incoming := "
                f"{_coq_list([_coq_bool(value) for value in incoming])} |}}.",
                "",
                f"Example {prefix}_certificate_is_admitted :",
                f"  admit_cfg_initialization_certificate {prefix}_certificate =",
                f"    Some {prefix}_certificate.",
                "Proof. reflexivity. Qed.",
                "",
                f"Theorem {prefix}_all_paths_are_initialized :",
                "  forall path,",
                f"    initialization_path_from {prefix}_graph 0 path ->",
                "    exists path_out,",
                f"      initialization_path_execute {prefix}_graph path false =",
                "        Some path_out.",
                "Proof.",
                "  intros path Hpath.",
                "  change (exists path_out,",
                "    initialization_path_execute",
                f"      (initialization_cfg {prefix}_certificate) path false =",
                "      Some path_out).",
                "  eapply admitted_cfg_initialization_certificate_paths_safe",
                f"    with (proposed := {prefix}_certificate)",
                f"      (accepted := {prefix}_certificate).",
                "  - reflexivity.",
                "  - exact Hpath.",
                "Qed.",
                "",
            ]
        )
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    arguments = parser.parse_args()
    try:
        admission = authority.validate(arguments.repo_root.resolve(), arguments.report)
        kernels = parse_verified_report(arguments.report.read_bytes())
        output = emit_rocq(kernels, admission.plan.root)
        arguments.output.write_text(output, encoding="utf-8", newline="\n")
    except (authority.PlanAuthorityError, CertificateError, OSError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
