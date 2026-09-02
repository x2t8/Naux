#!/usr/bin/env python3
"""Translate an admitted WP8C report into Rocq initialization certificates.

The Python translation is not trusted for the theorem.  It first replays the
existing sealed WP8C authority, emits only fixed Rocq constructors and numeric
block identifiers, and leaves initialization, operand, and projected-semantic
admission to executable checkers and proofs inside the Rocq kernel.
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
    scalar_actions: list[str] = field(default_factory=list)
    heap_actions: list[str] = field(default_factory=list)
    ownership_actions: list[str] = field(default_factory=list)
    raw_instruction_count: int = 0
    control_terminator: str | None = None
    successors: list[int] | None = None


@dataclass
class Kernel:
    ordinal: str
    name: str
    declared_blocks: int
    home_slot: int
    blocks: list[Block] = field(default_factory=list)


def _unsigned(raw: str, label: str) -> int:
    if not raw or (raw != "0" and raw.startswith("0")) or not raw.isascii() or not raw.isdigit():
        raise CertificateError(f"{label} is not a canonical unsigned integer")
    return int(raw)


def _target(raw: str, label: str) -> int:
    if not raw.startswith("b"):
        raise CertificateError(f"{label} is not a canonical block target")
    return _unsigned(raw[1:], label)


def _slot(raw: str, label: str) -> int:
    if not raw.startswith("s"):
        raise CertificateError(f"{label} is not a canonical stack slot")
    return _unsigned(raw[1:], label)


def _virtual_i64_register(raw: str, label: str) -> int:
    """Inject an i64 virtual register into a namespace disjoint from r12.

    Rocq register 0 denotes the physical resident home.  Virtual register rN
    is encoded as S N, so a source virtual r12 never aliases physical r12.
    """

    register, separator, machine_type = raw.partition(":")
    if separator != ":" or machine_type != "i64" or not register.startswith("r"):
        raise CertificateError(f"{label} is not a canonical i64 virtual register")
    return _unsigned(register[1:], label) + 1


def _virtual_bool_register(raw: str, label: str) -> int:
    register, separator, machine_type = raw.partition(":")
    if separator != ":" or machine_type != "bool" or not register.startswith("r"):
        raise CertificateError(f"{label} is not a canonical bool virtual register")
    return _unsigned(register[1:], label) + 1


def _virtual_typed_register(raw: str, expected_type: str, label: str) -> int:
    register, separator, machine_type = raw.partition(":")
    if (
        separator != ":"
        or machine_type != expected_type
        or not register.startswith("r")
    ):
        raise CertificateError(
            f"{label} is not a canonical {expected_type} virtual register"
        )
    return _unsigned(register[1:], label) + 1


def _signed_i64(raw: str, label: str) -> int:
    if raw.startswith("-"):
        magnitude = raw[1:]
        if not magnitude or magnitude == "0" or magnitude.startswith("0"):
            raise CertificateError(f"{label} is not a canonical signed integer")
        if not magnitude.isascii() or not magnitude.isdigit():
            raise CertificateError(f"{label} is not a canonical signed integer")
    else:
        _unsigned(raw, label)
    value = int(raw)
    if value < -(1 << 63) or value > (1 << 63) - 1:
        raise CertificateError(f"{label} is outside i64")
    return value


def _coq_z(value: int) -> str:
    return f"({value}%Z)"


def _coq_nat(value: int) -> str:
    return f"{value}%nat"


def _physical_action(parts: list[str]) -> str | None:
    opcode = parts[4]
    if opcode == "store-physical":
        if len(parts) != 8 or parts[5] != "r12":
            raise CertificateError("store-physical is outside the one-hot r12 model")
        source = _virtual_i64_register(parts[6], "store-physical source")
        if parts[7] not in {"keep", "consume"}:
            raise CertificateError("store-physical ownership mode is not canonical")
        return f"StoreHome {_coq_nat(source)}"
    if opcode == "load-physical":
        if len(parts) != 7 or parts[6] != "r12":
            raise CertificateError("load-physical is outside the one-hot r12 model")
        destination = _virtual_i64_register(parts[5], "load-physical destination")
        return f"LoadHome {_coq_nat(destination)}"
    if opcode == "add-physical-const":
        if len(parts) != 7 or parts[5] != "r12":
            raise CertificateError("add-physical-const is outside the one-hot r12 model")
        value = _signed_i64(parts[6], "add-physical-const value")
        return f"UpdateHome (AddConst {_coq_z(value)})"
    if "physical" in opcode:
        raise CertificateError(f"unsupported physical instruction {opcode!r}")
    return None


def _scalar_action(parts: list[str]) -> str | None:
    """Translate the exact scalar subset retained by the Rocq projection.

    Heap/list/ownership operations are deliberately omitted.  Any scalar-like
    opcode outside the closed subset fails instead of silently widening the
    theorem boundary.
    """

    opcode = parts[4]
    if opcode == "const-i64":
        if len(parts) != 7:
            raise CertificateError("const-i64 is malformed")
        destination = _virtual_i64_register(parts[5], "const-i64 destination")
        value = _signed_i64(parts[6], "const-i64 value")
        return f"ScalarConst {_coq_nat(destination)} {_coq_z(value)}"
    if opcode == "load-slot":
        if len(parts) != 7:
            raise CertificateError("load-slot is malformed")
        if parts[5].endswith(":owned-list-i64"):
            _slot(parts[6], "load-slot source")
            return None
        destination = _virtual_i64_register(parts[5], "load-slot destination")
        slot = _slot(parts[6], "load-slot source")
        return f"ScalarLoadSlot {_coq_nat(destination)} {_coq_nat(slot)}"
    if opcode == "store-slot":
        if len(parts) != 8 or parts[7] not in {"keep", "consume"}:
            raise CertificateError("store-slot is malformed")
        slot = _slot(parts[5], "store-slot destination")
        if parts[6].endswith(":owned-list-i64") or parts[6].endswith(":unit"):
            return None
        source = _virtual_i64_register(parts[6], "store-slot source")
        return f"ScalarStoreSlot {_coq_nat(slot)} {_coq_nat(source)}"
    if opcode == "add-slot-const":
        if len(parts) != 7:
            raise CertificateError("add-slot-const is malformed")
        slot = _slot(parts[5], "add-slot-const destination")
        value = _signed_i64(parts[6], "add-slot-const value")
        return f"ScalarAddSlotConst {_coq_nat(slot)} {_coq_z(value)}"
    binary_operations = {
        "i64-add": "ScalarAdd",
        "i64-sub": "ScalarSub",
        "i64-mul": "ScalarMul",
    }
    if opcode in binary_operations:
        if len(parts) != 8:
            raise CertificateError(f"{opcode} is malformed")
        destination = _virtual_i64_register(parts[5], f"{opcode} destination")
        left = _virtual_i64_register(parts[6], f"{opcode} left operand")
        right = _virtual_i64_register(parts[7], f"{opcode} right operand")
        return (
            f"ScalarBinary {_coq_nat(destination)} {binary_operations[opcode]} "
            f"{_coq_nat(left)} {_coq_nat(right)}"
        )
    compare_operations = {
        "i64-eq": "ScalarEq",
        "i64-ne": "ScalarNe",
        "i64-gt": "ScalarGt",
        "i64-ge": "ScalarGe",
        "i64-lt": "ScalarLt",
        "i64-le": "ScalarLe",
    }
    if opcode in compare_operations:
        if len(parts) != 8:
            raise CertificateError(f"{opcode} is malformed")
        destination = _virtual_bool_register(parts[5], f"{opcode} destination")
        left = _virtual_i64_register(parts[6], f"{opcode} left operand")
        right = _virtual_i64_register(parts[7], f"{opcode} right operand")
        return (
            f"ScalarCompare {_coq_nat(destination)} {compare_operations[opcode]} "
            f"{_coq_nat(left)} {_coq_nat(right)}"
        )
    if opcode.startswith("i64-"):
        raise CertificateError(f"unsupported scalar instruction {opcode!r}")
    if opcode in {
        "range-allocate-init",
        "list-length-static",
        "list-load-checked",
        "list-store-checked",
        "release-owned-list",
    }:
        return None
    if "physical" not in opcode:
        raise CertificateError(f"unknown pass-through instruction {opcode!r}")
    return None


def _heap_action(parts: list[str], scalar_action: str | None) -> str | None:
    """Translate every operation in the bounded heap/list projection.

    Ordinary scalar and physical operations reuse their already-closed
    constructors.  Owned-list handles and unit values are cell values in this
    projection; consuming moves do not model undefined source cells.
    """

    physical_action = _physical_action(parts)
    if physical_action is not None:
        return f"HeapScalarInstruction (ResidencyAccess ({physical_action}))"
    if scalar_action is not None:
        return f"HeapScalarInstruction (ScalarPassThrough ({scalar_action}))"

    opcode = parts[4]
    if opcode == "load-slot":
        if len(parts) != 7:
            raise CertificateError("load-slot is malformed")
        _, separator, machine_type = parts[5].partition(":")
        if separator != ":" or machine_type not in {"owned-list-i64", "unit"}:
            raise CertificateError("load-slot type is outside the heap projection")
        destination = _virtual_typed_register(
            parts[5], machine_type, "load-slot destination"
        )
        slot = _slot(parts[6], "load-slot source")
        return (
            "HeapScalarInstruction (ScalarPassThrough "
            f"(ScalarLoadSlot {_coq_nat(destination)} {_coq_nat(slot)}))"
        )
    if opcode == "store-slot":
        if len(parts) != 8 or parts[7] not in {"keep", "consume"}:
            raise CertificateError("store-slot is malformed")
        _, separator, machine_type = parts[6].partition(":")
        if separator != ":" or machine_type not in {"owned-list-i64", "unit"}:
            raise CertificateError("store-slot type is outside the heap projection")
        slot = _slot(parts[5], "store-slot destination")
        source = _virtual_typed_register(parts[6], machine_type, "store-slot source")
        return (
            "HeapScalarInstruction (ScalarPassThrough "
            f"(ScalarStoreSlot {_coq_nat(slot)} {_coq_nat(source)}))"
        )
    if opcode == "range-allocate-init":
        if len(parts) != 7:
            raise CertificateError("range-allocate-init is malformed")
        destination = _virtual_typed_register(
            parts[5], "owned-list-i64", "range allocation destination"
        )
        length = _unsigned(parts[6], "range allocation length")
        return (
            "HeapPassThrough "
            f"(HeapRangeAllocateInit {_coq_nat(destination)} {_coq_nat(length)})"
        )
    if opcode == "list-length-static":
        if len(parts) != 8:
            raise CertificateError("list-length-static is malformed")
        destination = _virtual_i64_register(parts[5], "list length destination")
        slot = _slot(parts[6], "list length source")
        length = _unsigned(parts[7], "static list length")
        return (
            "HeapPassThrough "
            f"(HeapListLengthStatic {_coq_nat(destination)} "
            f"{_coq_nat(slot)} {_coq_nat(length)})"
        )
    if opcode == "list-load-checked":
        if len(parts) != 8:
            raise CertificateError("list-load-checked is malformed")
        destination = _virtual_i64_register(parts[5], "list load destination")
        list_register = _virtual_typed_register(
            parts[6], "owned-list-i64", "list load owner"
        )
        index_register = _virtual_i64_register(parts[7], "list load index")
        return (
            "HeapPassThrough "
            f"(HeapListLoadChecked {_coq_nat(destination)} "
            f"{_coq_nat(list_register)} {_coq_nat(index_register)})"
        )
    if opcode == "list-store-checked":
        if len(parts) != 9:
            raise CertificateError("list-store-checked is malformed")
        destination = _virtual_typed_register(
            parts[5], "unit", "list store destination"
        )
        list_register = _virtual_typed_register(
            parts[6], "owned-list-i64", "list store owner"
        )
        index_register = _virtual_i64_register(parts[7], "list store index")
        value_register = _virtual_i64_register(parts[8], "list store value")
        return (
            "HeapPassThrough "
            f"(HeapListStoreChecked {_coq_nat(destination)} "
            f"{_coq_nat(list_register)} {_coq_nat(index_register)} "
            f"{_coq_nat(value_register)})"
        )
    if opcode == "release-owned-list":
        if len(parts) != 6:
            raise CertificateError("release-owned-list is malformed")
        slot = _slot(parts[5], "release source")
        return f"HeapPassThrough (HeapReleaseOwnedList {_coq_nat(slot)})"
    return None


def _ownership_action(parts: list[str], heap_action: str) -> str:
    """Retain the report's keep/consume bit around the exact heap projection."""

    opcode = parts[4]
    if opcode == "store-physical":
        if len(parts) != 8 or parts[5] != "r12":
            raise CertificateError("store-physical is outside the one-hot r12 model")
        source = _virtual_i64_register(parts[6], "store-physical source")
        if parts[7] not in {"keep", "consume"}:
            raise CertificateError("store-physical ownership mode is not canonical")
        return (
            f"OwnershipStoreHome {_coq_nat(source)} "
            f"{_coq_bool(parts[7] == 'keep')}"
        )
    if opcode == "store-slot":
        if len(parts) != 8 or parts[7] not in {"keep", "consume"}:
            raise CertificateError("store-slot is malformed")
        slot = _slot(parts[5], "store-slot destination")
        _, separator, machine_type = parts[6].partition(":")
        if separator != ":" or machine_type not in {
            "i64",
            "owned-list-i64",
            "unit",
        }:
            raise CertificateError("store-slot type is outside the ownership projection")
        source = _virtual_typed_register(
            parts[6], machine_type, "store-slot source"
        )
        return (
            f"OwnershipStoreSlot {_coq_nat(slot)} {_coq_nat(source)} "
            f"{_coq_bool(parts[7] == 'keep')}"
        )
    return f"OwnershipPlain ({heap_action})"


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


def _control_terminator(parts: list[str]) -> str:
    opcode = parts[3]
    if opcode == "goto" and len(parts) == 5:
        target = _target(parts[4], "goto target")
        return f"OwnershipControlGoto {_coq_nat(target)}"
    if opcode == "branch" and len(parts) == 7:
        condition = _virtual_bool_register(parts[4], "branch condition")
        if_true = _target(parts[5], "true target")
        if_false = _target(parts[6], "false target")
        return (
            f"OwnershipControlBranch {_coq_nat(condition)} "
            f"{_coq_nat(if_true)} {_coq_nat(if_false)}"
        )
    if opcode == "return" and len(parts) == 5:
        result = _virtual_i64_register(parts[4], "return result")
        return f"OwnershipControlReturn {_coq_nat(result)}"
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
                home_slot=_slot(parts[6], "kernel resident home"),
            )
            if parts[7] != "i64" or parts[8] != "r12":
                raise CertificateError(
                    f"line {line_number}: kernel is outside the one-hot i64/r12 model"
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
                raise CertificateError(
                    f"line {line_number}: instruction belongs to another kernel"
                )
            if _unsigned(parts[2], "instruction block") != current_block.block_id:
                raise CertificateError(f"line {line_number}: instruction block drifted")
            instruction_id = _unsigned(parts[3], "instruction id")
            if instruction_id != current_block.raw_instruction_count:
                raise CertificateError(f"line {line_number}: instruction ids are not contiguous")
            current_block.raw_instruction_count += 1
            physical_action = _physical_action(parts)
            if physical_action is not None:
                current_block.actions.append(physical_action)
                current_block.scalar_actions.append(
                    f"ResidencyAccess ({physical_action})"
                )
                heap_action = (
                    f"HeapScalarInstruction (ResidencyAccess ({physical_action}))"
                )
                current_block.heap_actions.append(heap_action)
            else:
                scalar_action = _scalar_action(parts)
                if scalar_action is not None:
                    current_block.scalar_actions.append(
                        f"ScalarPassThrough ({scalar_action})"
                    )
                heap_action = _heap_action(parts, scalar_action)
                if heap_action is None:
                    raise CertificateError(
                        f"line {line_number}: instruction is outside the heap projection"
                    )
                current_block.heap_actions.append(heap_action)
            current_block.ownership_actions.append(
                _ownership_action(parts, heap_action)
            )
        elif row == "terminator":
            if current_kernel is None or current_block is None or len(parts) < 4:
                raise CertificateError(f"line {line_number}: terminator is outside a block")
            if parts[1] != current_kernel.ordinal:
                raise CertificateError(f"line {line_number}: terminator belongs to another kernel")
            if _unsigned(parts[2], "terminator block") != current_block.block_id:
                raise CertificateError(f"line {line_number}: terminator block drifted")
            if current_block.raw_instruction_count != current_block.declared_instructions:
                raise CertificateError(f"line {line_number}: instruction extent drifted")
            current_block.control_terminator = _control_terminator(parts)
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
            if block.control_terminator is None:
                raise CertificateError(
                    f"kernel {kernel.ordinal} block b{block.block_id} "
                    "lacks a control terminator"
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
        "  The translation is untrusted; every certificate and projected",
        "  operand trace is admitted again inside the Rocq kernel.",
        "  Register 0 is physical r12; virtual rN is injected as S N.",
        "  Heap/list effects are retained by a partial successful-execution",
        "  model. Exact keep/consume definedness and release invalidation are",
        "  retained, including signed-i64 wrapping and overflow-event counts.",
        "  Exact terminator operands, per-block selection parity, and bounded",
        "  dynamic CFG path construction are retained. Host failures, counter",
        "  exhaustion, unbounded termination, and native semantics remain",
        "  explicit non-claims.",
        "*)",
        "",
        "From Stdlib Require Import List ZArith.",
        "From NauxCore Require Import RegisterResidency DefiniteInitialization",
        "  ProjectedCFGResidency ScalarMachineIRResidency",
        "  HeapMachineIRResidency OwnershipMachineIRResidency",
        "  ControlFlowMachineIRResidency.",
        "Import ListNotations.",
        "",
    ]
    for kernel in kernels:
        if any(block.control_terminator is None for block in kernel.blocks):
            raise CertificateError(
                f"kernel {kernel.ordinal} has an unmodeled control terminator"
            )
        reachable, incoming = derive_must_facts(kernel)
        prefix = f"wp8c_kernel_{kernel.ordinal}"
        block_rows = [_coq_list(block.actions) for block in kernel.blocks]
        scalar_block_rows = [
            _coq_list(block.scalar_actions) for block in kernel.blocks
        ]
        heap_block_rows = [_coq_list(block.heap_actions) for block in kernel.blocks]
        ownership_block_rows = [
            _coq_list(block.ownership_actions) for block in kernel.blocks
        ]
        control_block_rows = [
            "{| ownership_control_instructions := "
            f"{_coq_list(block.ownership_actions)}; "
            "ownership_control_block_terminator := "
            f"{block.control_terminator} |}}"
            for block in kernel.blocks
        ]
        successor_rows = [
            _coq_list([_coq_nat(value) for value in block.successors or []])
            for block in kernel.blocks
        ]
        rows.extend(
            [
                f"Definition {prefix}_graph : initialization_graph :=",
                "  {| initialization_entry := 0%nat;",
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
                f"Definition {prefix}_scalar_graph : scalar_residency_graph :=",
                "  {| scalar_residency_entry := 0%nat;",
                "     scalar_residency_blocks := "
                f"{_coq_list(scalar_block_rows)};",
                f"     scalar_residency_successors := {_coq_list(successor_rows)} |}}.",
                "",
                f"Example {prefix}_scalar_graph_projects_exactly :",
                f"  scalar_residency_graph_projection {prefix}_scalar_graph =",
                f"    {prefix}_graph.",
                "Proof. reflexivity. Qed.",
                "",
                f"Theorem {prefix}_all_paths_are_initialized :",
                "  forall path,",
                f"    initialization_path_from {prefix}_graph 0%nat path ->",
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
                f"Theorem {prefix}_all_paths_preserve_projected_state :",
                "  forall path home_slot initial replacement,",
                f"    initialization_path_from {prefix}_graph 0%nat path ->",
                "    exists program path_out candidate_out,",
                f"      projected_path_program {prefix}_graph path = Some program /\\",
                f"      initialization_path_execute {prefix}_graph path false =",
                "        Some path_out /\\",
                "      projected_candidate_execute 0%nat false program",
                "        (hide_reserved_register 0%nat replacement initial) =",
                "        Some (path_out, candidate_out) /\\",
                "      full_state_equiv",
                "        (baseline_execute home_slot program initial)",
                "        (projected_finalize home_slot 0%nat",
                "          (register_cells initial 0%nat) path_out candidate_out).",
                "Proof.",
                "  intros path home_slot initial replacement Hpath.",
                "  eapply admitted_cfg_all_projected_paths_abi_correct",
                f"    with (proposed := {prefix}_certificate)",
                f"      (accepted := {prefix}_certificate).",
                "  - reflexivity.",
                "  - reflexivity.",
                "  - exact Hpath.",
                "Qed.",
                "",
                f"Theorem {prefix}_all_paths_preserve_scalar_projection :",
                "  forall path initial replacement,",
                f"    initialization_path_from {prefix}_graph 0%nat path ->",
                "    exists program path_out candidate_out,",
                f"      scalar_residency_path_program {prefix}_scalar_graph path =",
                "        Some program /\\",
                f"      initialization_path_execute {prefix}_graph path false =",
                "        Some path_out /\\",
                "      scalar_residency_candidate_execute 0%nat false program",
                "        (hide_reserved_register 0%nat replacement initial) =",
                "        Some (path_out, candidate_out) /\\",
                "      full_state_equiv",
                f"        (scalar_residency_baseline_execute {_coq_nat(kernel.home_slot)}",
                "          program initial)",
                f"        (projected_finalize {_coq_nat(kernel.home_slot)} 0%nat",
                "          (register_cells initial 0%nat) path_out candidate_out).",
                "Proof.",
                "  intros path initial replacement Hpath.",
                "  eapply admitted_cfg_all_scalar_residency_paths_abi_correct",
                f"    with (proposed := {prefix}_certificate)",
                f"      (accepted := {prefix}_certificate).",
                "  - reflexivity.",
                "  - reflexivity.",
                "  - reflexivity.",
                "  - exact Hpath.",
                "Qed.",
                "",
                f"Definition {prefix}_heap_graph : heap_residency_graph :=",
                "  {| heap_residency_entry := 0%nat;",
                "     heap_residency_blocks := "
                f"{_coq_list(heap_block_rows)};",
                f"     heap_residency_successors := {_coq_list(successor_rows)} |}}.",
                "",
                f"Example {prefix}_heap_graph_projects_exactly :",
                f"  heap_residency_graph_projection {prefix}_heap_graph =",
                f"    {prefix}_graph.",
                "Proof. reflexivity. Qed.",
                "",
                f"Theorem {prefix}_all_successful_paths_preserve_heap_projection :",
                "  forall path initial replacement baseline_out,",
                f"    initialization_path_from {prefix}_graph 0%nat path ->",
                "    (exists program,",
                f"      heap_residency_path_program {prefix}_heap_graph path =",
                "        Some program /\\",
                f"      heap_residency_baseline_execute {_coq_nat(kernel.home_slot)}",
                "        program initial = Some baseline_out) ->",
                "    exists program path_out candidate_out,",
                f"      heap_residency_path_program {prefix}_heap_graph path =",
                "        Some program /\\",
                f"      initialization_path_execute {prefix}_graph path false =",
                "        Some path_out /\\",
                f"      heap_residency_baseline_execute {_coq_nat(kernel.home_slot)}",
                "        program initial = Some baseline_out /\\",
                "      heap_residency_candidate_execute 0%nat false program",
                "        (heap_hide_reserved_register 0%nat replacement initial) =",
                "        Some (path_out, candidate_out) /\\",
                "      heap_full_state_equiv baseline_out",
                f"        (heap_finalize {_coq_nat(kernel.home_slot)} 0%nat",
                "          (register_cells (heap_scalar_state initial) 0%nat)",
                "          path_out candidate_out).",
                "Proof.",
                "  intros path initial replacement baseline_out Hpath Hsuccess.",
                "  eapply admitted_cfg_all_heap_residency_paths_abi_correct",
                f"    with (proposed := {prefix}_certificate)",
                f"      (accepted := {prefix}_certificate).",
                "  - reflexivity.",
                "  - reflexivity.",
                "  - reflexivity.",
                "  - exact Hpath.",
                "  - exact Hsuccess.",
                "Qed.",
                "",
                f"Definition {prefix}_ownership_graph : ownership_residency_graph :=",
                "  {| ownership_residency_entry := 0%nat;",
                "     ownership_residency_blocks := "
                f"{_coq_list(ownership_block_rows)};",
                "     ownership_residency_successors := "
                f"{_coq_list(successor_rows)} |}}.",
                "",
                f"Example {prefix}_ownership_graph_projects_exactly :",
                "  ownership_residency_graph_projection",
                f"    {prefix}_ownership_graph = {prefix}_heap_graph.",
                "Proof. reflexivity. Qed.",
                "",
                f"Example {prefix}_ownership_graph_is_admissible :",
                "  ownership_residency_graph_admissibleb",
                f"    {_coq_nat(kernel.home_slot)} 0%nat",
                f"    {prefix}_ownership_graph = true.",
                "Proof. reflexivity. Qed.",
                "",
                f"Definition {prefix}_control_graph : ownership_control_graph :=",
                f"  {{| ownership_control_entry := 0%nat;",
                "     ownership_control_blocks := "
                f"{_coq_list(control_block_rows)} |}}.",
                "",
                f"Example {prefix}_control_graph_projects_exactly :",
                "  ownership_control_graph_projection",
                f"    {prefix}_control_graph = {prefix}_ownership_graph.",
                "Proof. reflexivity. Qed.",
                "",
                f"Example {prefix}_control_graph_is_admissible :",
                "  ownership_control_graph_admissibleb",
                f"    {_coq_nat(kernel.home_slot)} 0%nat",
                f"    {prefix}_control_graph = true.",
                "Proof. reflexivity. Qed.",
                "",
                f"Theorem {prefix}_every_successful_control_block_preserves_selection :",
                "  forall block_id block initialized next baseline candidate",
                "      baseline_out outcome,",
                "    nth_error (ownership_control_blocks",
                f"      {prefix}_control_graph) block_id = Some block ->",
                "    initialization_block initialized",
                "      (ownership_residency_program_projection",
                "        (ownership_control_instructions block)) = Some next ->",
                "    ownership_projected_phase_equiv",
                f"      {_coq_nat(kernel.home_slot)} 0%nat initialized",
                "      baseline candidate ->",
                "    ownership_control_baseline_block",
                f"      {_coq_nat(kernel.home_slot)} block baseline =",
                "      Some (baseline_out, outcome) ->",
                "    exists candidate_out,",
                "      ownership_control_candidate_block",
                f"        {_coq_nat(kernel.home_slot)} 0%nat initialized",
                "        block candidate = Some (next, (candidate_out, outcome)) /\\",
                "      ownership_projected_phase_equiv",
                f"        {_coq_nat(kernel.home_slot)} 0%nat next",
                "        baseline_out candidate_out.",
                "Proof.",
                "  intros block_id block initialized next baseline candidate",
                "    baseline_out outcome Hblock Hinitialization Hphase Hbaseline.",
                "  eapply ownership_control_graph_block_preserves_selection",
                f"    with (graph := {prefix}_control_graph)",
                "      (block_id := block_id).",
                "  - reflexivity.",
                "  - exact Hblock.",
                "  - exact Hinitialization.",
                "  - exact Hphase.",
                "  - exact Hbaseline.",
                "Qed.",
                "",
                f"Theorem {prefix}_all_successful_bounded_control_executions_preserve_selection :",
                "  forall fuel initial replacement final_initialized",
                "      baseline_out value,",
                "    ownership_control_baseline_execute fuel",
                f"      {_coq_nat(kernel.home_slot)} {prefix}_control_graph",
                "      0%nat false initial =",
                "      Some (final_initialized, (baseline_out, value)) ->",
                "    exists candidate_out,",
                "      ownership_control_candidate_execute fuel",
                f"        {_coq_nat(kernel.home_slot)} 0%nat",
                f"        {prefix}_control_graph 0%nat false",
                "        (ownership_hide_reserved_register",
                "          0%nat replacement initial) =",
                "        Some (final_initialized, (candidate_out, value)) /\\",
                "      ownership_projected_phase_equiv",
                f"        {_coq_nat(kernel.home_slot)} 0%nat final_initialized",
                "        baseline_out candidate_out.",
                "Proof.",
                "  intros fuel initial replacement final_initialized",
                "    baseline_out value Hbaseline.",
                "  eapply ownership_control_execution_preserves_selection",
                f"    with (graph := {prefix}_control_graph)",
                "      (block_id := 0%nat).",
                "  - reflexivity.",
                "  - apply ownership_hide_reserved_register_preserves_phase.",
                "  - exact Hbaseline.",
                "Qed.",
                "",
                f"Theorem {prefix}_all_successful_bounded_control_executions_are_abi_correct :",
                "  forall fuel initial replacement final_initialized",
                "      baseline_out value,",
                "    ownership_control_baseline_execute fuel",
                f"      {_coq_nat(kernel.home_slot)} {prefix}_control_graph",
                "      0%nat false initial =",
                "      Some (final_initialized, (baseline_out, value)) ->",
                "    exists candidate_out,",
                "      ownership_control_candidate_execute fuel",
                f"        {_coq_nat(kernel.home_slot)} 0%nat",
                f"        {prefix}_control_graph 0%nat false",
                "        (ownership_hide_reserved_register",
                "          0%nat replacement initial) =",
                "        Some (final_initialized, (candidate_out, value)) /\\",
                "      ownership_full_state_equiv baseline_out",
                f"        (ownership_finalize {_coq_nat(kernel.home_slot)} 0%nat",
                "          (register_cells",
                "            (heap_scalar_state (ownership_heap_state initial))",
                "            0%nat)",
                "          final_initialized candidate_out).",
                "Proof.",
                "  intros fuel initial replacement final_initialized",
                "    baseline_out value Hbaseline.",
                "  eapply ownership_control_checked_abi_correct",
                f"    with (graph := {prefix}_control_graph).",
                "  - reflexivity.",
                "  - exact Hbaseline.",
                "Qed.",
                "",
                f"Theorem {prefix}_all_successful_paths_preserve_ownership_projection :",
                "  forall path initial replacement baseline_out,",
                f"    initialization_path_from {prefix}_graph 0%nat path ->",
                "    (exists program,",
                "      ownership_residency_path_program",
                f"        {prefix}_ownership_graph path = Some program /\\",
                f"      ownership_baseline_execute {_coq_nat(kernel.home_slot)}",
                "        program initial = Some baseline_out) ->",
                "    exists program path_out candidate_out,",
                "      ownership_residency_path_program",
                f"        {prefix}_ownership_graph path = Some program /\\",
                f"      initialization_path_execute {prefix}_graph path false =",
                "        Some path_out /\\",
                f"      ownership_baseline_execute {_coq_nat(kernel.home_slot)}",
                "        program initial = Some baseline_out /\\",
                "      ownership_candidate_execute",
                f"        {_coq_nat(kernel.home_slot)} 0%nat false program",
                "        (ownership_hide_reserved_register",
                "          0%nat replacement initial) =",
                "        Some (path_out, candidate_out) /\\",
                "      ownership_full_state_equiv baseline_out",
                f"        (ownership_finalize {_coq_nat(kernel.home_slot)} 0%nat",
                "          (register_cells",
                "            (heap_scalar_state (ownership_heap_state initial))",
                "            0%nat)",
                "          path_out candidate_out).",
                "Proof.",
                "  intros path initial replacement baseline_out Hpath Hsuccess.",
                "  eapply admitted_cfg_all_ownership_residency_paths_abi_correct",
                f"    with (proposed := {prefix}_certificate)",
                f"      (accepted := {prefix}_certificate).",
                "  - reflexivity.",
                "  - reflexivity.",
                "  - reflexivity.",
                "  - exact Hpath.",
                "  - exact Hsuccess.",
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
