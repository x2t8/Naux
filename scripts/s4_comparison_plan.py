#!/usr/bin/env python3
"""Prepare a draft r12/C comparison plan; never acquire or admit measurements.

This is an unsealed planning tool, not a successor measurement authority. It
checks existing carriers in the Apache checkout and an ephemeral LT1 historical
view, then prints a deterministic proposed schedule. No compiler, generated
image, host probe, network request, or performance evaluation is invoked.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import license_transition as lt1
import s4_c_timing_carriers as c_timing
import s4_register_residency_timing as candidate_timing
import s4_threshold_evaluator as thresholds


PLAN_MAGIC = "NAUX-S4-COMPARISON-PLAN\t1"
N = 16_384
REPS = 50
ROUNDS = 30
KERNEL_COUNT = 4


class ComparisonPlanError(ValueError):
    """The existing carriers do not support the proposed comparison."""


@dataclass(frozen=True)
class Role:
    owner: int
    name: str
    parameters: str


# These are result-record owners, NOT WP1's optional Rust role ordinals.
ROLES = (
    Role(4, "naux-register-residency-candidate", "static-n-and-reps"),
    Role(2, "c-generic", "runtime-n-and-reps"),
    Role(3, "c-specialized", "static-n-and-reps"),
)
ROLE_NAMES = {role.owner: role.name for role in ROLES}
# All six permutations, paired with their reverses. Five full cycles give each
# role ten visits to each position, and each pair fifteen visits in each order.
ROUND_ORDERS = ((4, 2, 3), (3, 2, 4), (2, 3, 4), (4, 3, 2), (3, 4, 2), (2, 4, 3))


@dataclass(frozen=True)
class PlannedInvocation:
    kernel: int
    round: int
    position: int
    owner: int


@dataclass(frozen=True)
class KernelPlan:
    ordinal: int
    name: str
    oracle: int
    work_hash: str
    candidate_elf_bytes: int
    candidate_elf_hash: str
    c_source: str
    c_source_hash: str


@dataclass(frozen=True)
class ComparisonPlan:
    parent_authorities: tuple[tuple[str, str], ...]
    kernels: tuple[KernelPlan, ...]
    schedule: tuple[PlannedInvocation, ...]


def measured_schedule() -> tuple[PlannedInvocation, ...]:
    """Return planned invocations only: there are no durations or observations."""
    return tuple(
        PlannedInvocation(kernel, round_number, position, owner)
        for kernel in range(1, KERNEL_COUNT + 1)
        for round_number in range(1, ROUNDS + 1)
        for position, owner in enumerate(ROUND_ORDERS[(round_number - 1) % 6], 1)
    )


def validate_schedule(schedule: tuple[PlannedInvocation, ...]) -> None:
    if len(schedule) != KERNEL_COUNT * ROUNDS * len(ROLES):
        raise ComparisonPlanError("comparison schedule must contain exactly 360 invocations")
    for step in schedule:
        if not isinstance(step, PlannedInvocation) or any(
            type(value) is not int
            for value in (step.kernel, step.round, step.position, step.owner)
        ):
            raise ComparisonPlanError("comparison schedule fields must be integer identities")
    if schedule != measured_schedule():
        raise ComparisonPlanError("comparison schedule order or role ownership drifted")


def _match_kernels(
    candidate: candidate_timing.Admission, reference: c_timing.Admission
) -> tuple[KernelPlan, ...]:
    targets = candidate.contract.records
    sources = reference.contract.kernels
    if len(targets) != KERNEL_COUNT or len(sources) != KERNEL_COUNT:
        raise ComparisonPlanError("comparison requires all four kernels from both carriers")
    kernels = []
    for ordinal, (target, source) in enumerate(zip(targets, sources), 1):
        if (
            target.ordinal != ordinal
            or source.ordinal != ordinal
            or target.name != source.name
            or target.oracle != source.oracle
        ):
            raise ComparisonPlanError("candidate/C kernel order, identity, or oracle mismatch")
        kernels.append(KernelPlan(
            ordinal, target.name, target.oracle, target.work_hash,
            target.elf_bytes, target.elf_hash, source.derived_path, source.derived_hash,
        ))
    return tuple(kernels)


def prepare(root: Path) -> ComparisonPlan:
    """Validate parents without reinterpreting any old measurement as new data."""
    root = root.resolve(strict=True)
    candidate = candidate_timing.validate(root)
    # Historical authorities bind pre-Apache files. Use the existing LT1 path;
    # do not rewrite their seals or restore old licenses into the actual tree.
    with tempfile.TemporaryDirectory(prefix="naux-comparison-plan-") as directory:
        historical = lt1.materialize_historical(root, Path(directory) / "repository")
        reference = c_timing.validate(historical)
        threshold = thresholds.validate(historical)
    if reference.authority.seal != thresholds.WP7B_C_AUTHORITY_SEAL:
        raise ComparisonPlanError("C timing authority does not match WP7D")
    if candidate.wrapper.authority.seal != thresholds.WP7B_NAUX_AUTHORITY_SEAL:
        raise ComparisonPlanError("candidate and C comparison do not share the timing wrapper")
    schedule = measured_schedule()
    validate_schedule(schedule)
    return ComparisonPlan(
        (
            ("candidate-timing", candidate.authority.seal),
            ("c-timing", reference.authority.seal),
            ("legacy-threshold-policy", threshold.authority.seal),
        ),
        _match_kernels(candidate, reference),
        schedule,
    )


def render(plan: ComparisonPlan, *, include_schedule: bool = False) -> bytes:
    validate_schedule(plan.schedule)
    rows = [
        PLAN_MAGIC,
        "status\tdraft-plan-only",
        "mode\tstatic-no-build-no-measurement",
        "execution-status\tforbidden",
        "claim-status\tnot-admitted",
        "scope4-exit\tnot-established",
        "result-owner-namespace\twp8j-and-c-timing-wire-owners-not-wp1-role-ordinals",
        "target\tx86_64-unknown-linux-gnu",
        f"dataset\tn16384-r50-v1\t{N}\t{REPS}",
        "runtime-region\tallocation-initialization-kernel-checksum-teardown",
        "clock-source\tclock-monotonic-raw-direct-syscall",
        "result-protocol\tfixed-le56-v1",
        "cross-session-ratio\tforbidden",
        "candidate-relabel-as-legacy-residual\tforbidden",
        "warmup\tall-three-roles-at-least-100000000-ns-each-retain-every-invocation",
        "outlier-policy\treport-all-no-hidden-drop-no-retry",
        "variance-policy\tall-twelve-statistics-cv-not-greater-than-5-percent",
        "competitiveness\tcandidate-median-over-c-specialized-median<=11/10",
        "differentiation\tc-generic-median-over-candidate-median>=5/4",
        "intersection\tat-least-one-same-kernel-passes-both",
        "schedule-policy\tall-six-orders-repeated-five-times-per-kernel",
        "planned-samples-per-role-per-kernel\t30",
        "planned-measured-invocations\t360",
        "observed-measured-invocations\t0",
        f"c-generic-argv\t{N}\t{REPS}",
        "rust-comparison\tnot-in-this-plan",
        "cpp-comparison\tnot-in-this-plan",
    ]
    rows.extend(f"parent\t{name}\t{seal}" for name, seal in plan.parent_authorities)
    rows.extend(f"role\t{r.owner}\t{r.name}\t{r.parameters}" for r in ROLES)
    rows.extend(f"c-common-flag\t{flag}" for flag in c_timing.COMMON_FLAGS)
    rows.extend(f"c-specialized-flag\t{flag}" for flag in c_timing.SPECIALIZED_FLAGS)
    for kernel in plan.kernels:
        rows.extend((
            f"kernel\t{kernel.ordinal:02}\t{kernel.name}\t{kernel.oracle}\t{kernel.work_hash}",
            f"candidate-expected-elf\t{kernel.ordinal:02}\t{kernel.candidate_elf_bytes}"
            f"\t{kernel.candidate_elf_hash}",
            f"c-timing-source\t{kernel.ordinal:02}\t{kernel.c_source}\t{kernel.c_source_hash}",
        ))
    rows.extend((
        "pending\tmeasurement-authority\tnew-three-role-host-runner-and-bundle-protocol",
        "pending\tfresh-builds\tsame-checkout-resolved-tools-and-twelve-verified-artifacts",
        "pending\tcontrolled-host\tfresh-suite-specific-retained-and-live-attestation",
        "pending\tevidence\tall-warmups-and-360-ordered-samples-in-one-new-session",
        "pending\treplay\tnew-role-aware-bundle-replay-and-exact-threshold-evaluation",
        "pending\tcost-separation\tcompile-specialize-startup-memory-and-code-size-evidence",
        "pending\tpublic-comparison\treplayable-artifacts-and-distinct-claim-approval",
        "pending\trelease-regression\tadmitted-reference-and-enforced-release-gate",
    ))
    if include_schedule:
        rows.extend(
            f"planned-run\t{s.kernel:02}\t{s.round:02}\t{s.position}\t{s.owner}"
            f"\t{ROLE_NAMES[s.owner]}"
            for s in plan.schedule
        )
    return ("\n".join(rows) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--schedule", action="store_true", help="include every planned invocation")
    arguments = parser.parse_args(argv)
    try:
        report = render(prepare(arguments.root), include_schedule=arguments.schedule)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"S4 comparison planning failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
