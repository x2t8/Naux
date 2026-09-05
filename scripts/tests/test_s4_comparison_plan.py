from __future__ import annotations

import hashlib
import io
import itertools
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from dataclasses import replace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import s4_comparison_plan as comparison


class ComparisonScheduleTests(unittest.TestCase):
    def test_all_kernels_receive_30_complete_three_role_rounds(self) -> None:
        schedule = comparison.measured_schedule()
        comparison.validate_schedule(schedule)
        self.assertEqual(len(schedule), 360)
        self.assertEqual(
            Counter((s.kernel, s.owner) for s in schedule),
            {(kernel, owner): 30 for kernel in range(1, 5) for owner in (4, 2, 3)},
        )
        for kernel in range(1, 5):
            for round_number in range(1, 31):
                steps = [s for s in schedule if (s.kernel, s.round) == (kernel, round_number)]
                self.assertEqual([s.position for s in steps], [1, 2, 3])
                self.assertEqual({s.owner for s in steps}, {4, 2, 3})

    def test_position_and_pairwise_order_are_balanced_for_every_kernel(self) -> None:
        schedule = comparison.measured_schedule()
        for kernel in range(1, 5):
            rounds = [
                tuple(s.owner for s in schedule if (s.kernel, s.round) == (kernel, number))
                for number in range(1, 31)
            ]
            self.assertEqual(Counter(rounds), {order: 5 for order in itertools.permutations((4, 2, 3))})
            for owner in (4, 2, 3):
                self.assertEqual(Counter(order.index(owner) for order in rounds), {0: 10, 1: 10, 2: 10})
            for left, right in itertools.permutations((4, 2, 3), 2):
                self.assertEqual(sum(order.index(left) < order.index(right) for order in rounds), 15)

    def test_missing_duplicate_reordered_and_relabelled_steps_are_rejected(self) -> None:
        original = comparison.measured_schedule()
        variants = {
            "missing": original[:-1],
            "extra": original + original[-1:],
            "duplicate": (original[1],) + original[1:],
            "reordered": (original[1], original[0]) + original[2:],
            "baseline substituted": (replace(original[0], owner=1),) + original[1:],
            "unknown role": (replace(original[0], owner=5),) + original[1:],
            "wrong round": (replace(original[0], round=2),) + original[1:],
            "wrong kernel": (replace(original[0], kernel=2),) + original[1:],
            "boolean identity": (replace(original[0], kernel=True),) + original[1:],
        }
        for name, schedule in variants.items():
            with self.subTest(name=name), self.assertRaises(comparison.ComparisonPlanError):
                comparison.validate_schedule(schedule)

    def test_schedule_contains_no_timing_or_process_results(self) -> None:
        self.assertEqual(
            set(comparison.PlannedInvocation.__dataclass_fields__),
            {"kernel", "round", "position", "owner"},
        )
        self.assertEqual(comparison.ROLE_NAMES[4], "naux-register-residency-candidate")
        self.assertNotIn("rust-generic", comparison.ROLE_NAMES.values())


CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() == comparison.lt1.APACHE_HASH
)


@unittest.skipUnless(CURRENT_APACHE_SURFACE, "comparison planning requires the Apache-2.0 checkout")
class ComparisonPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.candidate = comparison.candidate_timing.validate(ROOT)
        with tempfile.TemporaryDirectory(prefix="naux-comparison-parents-") as directory:
            historical = comparison.lt1.materialize_historical(ROOT, Path(directory) / "repository")
            cls.reference = comparison.c_timing.validate(historical)
        cls.plan = comparison.prepare(ROOT)

    def test_real_parent_validation_is_deterministic_and_does_not_build_or_measure(self) -> None:
        paths = (
            ROOT / "LICENSE",
            ROOT / "distribution/s4-performance/WP7D-THRESHOLD.tsv",
            ROOT / "distribution/s4-performance/WP8S-APPROVED-CLAIM.txt",
        )
        before = [path.read_bytes() for path in paths]
        real_run = subprocess.run
        commands = []

        def only_inventory(argv, *args, **kwargs):
            self.assertEqual(argv, ["git", "-C", str(ROOT), "ls-files", "-z", "--cached"])
            commands.append(argv)
            return real_run(argv, *args, **kwargs)

        with (
            mock.patch("subprocess.run", side_effect=only_inventory),
            mock.patch("socket.socket", side_effect=AssertionError("no network")),
            mock.patch.object(comparison.candidate_timing, "_run_emitter", side_effect=AssertionError("no emitter")),
            mock.patch.object(comparison.c_timing, "compile_audit", side_effect=AssertionError("no C build")),
            mock.patch.object(comparison.thresholds.wp7c, "acquire", side_effect=AssertionError("no acquisition")),
            mock.patch.object(comparison.thresholds, "replay_bundle", side_effect=AssertionError("no old samples")),
        ):
            plan = comparison.prepare(ROOT)
        self.assertEqual(plan, self.plan)
        self.assertEqual(len(commands), 1)
        self.assertEqual([path.read_bytes() for path in paths], before)

    def test_plan_names_pending_gates_without_claiming_a_result(self) -> None:
        report = comparison.render(self.plan).decode()
        for row in (
            "status\tdraft-plan-only\n",
            "execution-status\tforbidden\n",
            "claim-status\tnot-admitted\n",
            "scope4-exit\tnot-established\n",
            "observed-measured-invocations\t0\n",
            "cross-session-ratio\tforbidden\n",
            "candidate-relabel-as-legacy-residual\tforbidden\n",
            "rust-comparison\tnot-in-this-plan\n",
            "cpp-comparison\tnot-in-this-plan\n",
        ):
            self.assertIn(row, report)
        self.assertIn("pending\trelease-regression\t", report)
        self.assertIn("pending\tcost-separation\t", report)
        self.assertNotIn("planned-run\t", report)
        self.assertNotIn("admitted-exact-observation", report)
        self.assertNotIn("sample\t", report)

    def test_runtime_boundary_thresholds_and_c_flags_stay_unchanged(self) -> None:
        report = comparison.render(self.plan).decode()
        for text in (
            "n16384-r50-v1\t16384\t50",
            "allocation-initialization-kernel-checksum-teardown",
            "candidate-median-over-c-specialized-median<=11/10",
            "c-generic-median-over-candidate-median>=5/4",
            "at-least-one-same-kernel-passes-both",
            "all-twelve-statistics-cv-not-greater-than-5-percent",
            "all-three-roles-at-least-100000000-ns-each-retain-every-invocation",
            "c-generic-argv\t16384\t50",
            "c-common-flag\t-O3",
            "c-common-flag\t-fno-fast-math",
            "c-common-flag\t-fno-lto",
        ):
            self.assertIn(text, report)

    def test_carrier_identities_are_not_replaced_with_old_observations(self) -> None:
        report = comparison.render(self.plan).decode()
        self.assertEqual(report.count("\ncandidate-expected-elf\t"), 4)
        self.assertEqual(report.count("\nc-timing-source\t"), 4)
        for kernel, target, source in zip(
            self.plan.kernels, self.candidate.contract.records, self.reference.contract.kernels
        ):
            self.assertEqual(kernel.candidate_elf_hash, target.elf_hash)
            self.assertEqual(kernel.c_source_hash, source.derived_hash)
            self.assertEqual(kernel.oracle, target.oracle)
        self.assertNotIn("c-expected-elf", report)  # C binaries still require fresh compilation.

    def test_matching_rejects_missing_duplicate_or_different_workloads(self) -> None:
        records = self.reference.contract.kernels
        variants = (
            records[:-1],
            (records[1],) + records[1:],
            (replace(records[0], oracle=0),) + records[1:],
            (replace(records[0], name="other-workload"),) + records[1:],
        )
        for changed in variants:
            reference = replace(self.reference, contract=replace(self.reference.contract, kernels=changed))
            with self.subTest(changed=changed[0]), self.assertRaises(comparison.ComparisonPlanError):
                comparison._match_kernels(self.candidate, reference)

    def test_schedule_output_is_explicit_and_reproducible(self) -> None:
        first = comparison.render(self.plan, include_schedule=True)
        self.assertEqual(first, comparison.render(self.plan, include_schedule=True))
        rows = [line.split("\t") for line in first.decode().splitlines() if line.startswith("planned-run\t")]
        self.assertEqual(len(rows), 360)
        self.assertEqual(rows[0], ["planned-run", "01", "01", "1", "4", "naux-register-residency-candidate"])
        self.assertEqual(rows[-1], ["planned-run", "04", "30", "3", "3", "c-specialized"])

    def test_cli_emits_no_partial_plan_when_a_parent_is_invalid(self) -> None:
        output, stderr = io.BytesIO(), io.StringIO()
        with (
            mock.patch.object(comparison, "prepare", side_effect=ValueError("invalid parent")),
            mock.patch.object(sys, "stdout", buffer=output),
            mock.patch.object(sys, "stderr", stderr),
        ):
            status = comparison.main(["--root", str(ROOT)])
        self.assertEqual((status, output.getvalue()), (1, b""))
        self.assertIn("invalid parent", stderr.getvalue())

    def test_cli_cannot_acquire_or_ingest_old_evidence(self) -> None:
        for option in ("--acquire", "--bundle", "--archive", "--receipt", "--cc", "--host-attestation"):
            with (
                self.subTest(option=option),
                mock.patch.object(comparison, "prepare") as prepare,
                mock.patch.object(sys, "stderr", io.StringIO()),
                self.assertRaises(SystemExit) as caught,
            ):
                comparison.main([option])
            self.assertEqual(caught.exception.code, 2)
            prepare.assert_not_called()


if __name__ == "__main__":
    unittest.main()
