#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_performance_gap_forensics.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_performance_gap_forensics_replay", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
forensics = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = forensics
SPEC.loader.exec_module(forensics)


class S4PerformanceGapForensicsReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.admission = forensics.validate(ROOT)
        value = os.environ.get("NAUX_S4_WP5D_EMITTER")
        if not value:
            raise unittest.SkipTest("reviewed WP5D emitter is unavailable")
        cls.emitter = (ROOT / value).resolve() if not Path(value).is_absolute() else Path(value)
        bundle = os.environ.get("NAUX_S4_WP7C_BUNDLE")
        cls.bundle = None if not bundle else (
            (ROOT / bundle).resolve() if not Path(bundle).is_absolute() else Path(bundle)
        )
        _report, cls.candidate = forensics.wp5d.replay(
            cls.admission.wp5d_admission, cls.emitter
        )

    @classmethod
    def _artifacts(cls) -> tuple[bytes, ...]:
        artifacts: list[bytes] = []
        for kernel, process, timing in zip(
            cls.candidate.kernels,
            cls.admission.wp5e_admission.contract.records,
            cls.admission.wp7b_admission.contract.records,
            strict=True,
        ):
            process_target = forensics.wp5e._reconstruct_process_target(process, kernel.target)
            artifacts.append(forensics.wp7b._reconstruct_elf(timing, process_target))
        return tuple(artifacts)

    def test_exact_chain_and_bounded_profiles_reproduce_all_oracles(self) -> None:
        kernels = forensics.bind_artifact_chain(
            self._artifacts(),
            self.candidate,
            self.admission.wp7b_admission.contract,
            self.admission.wp5e_admission.contract,
        )
        self.assertEqual(len(kernels), 4)
        for kernel in kernels:
            profile = forensics.interpret_plan(
                kernel.wp5d_kernel, kernel.process_record.oracle
            )
            self.assertEqual(profile.result, kernel.process_record.oracle)
            self.assertGreater(profile.steps, 0)
            self.assertEqual(sum(profile.block_visits), sum(profile.terminator_visits))

    def test_only_implicit_gotos_may_lack_source_correspondence(self) -> None:
        missing_by_kernel: list[int] = []
        for kernel in self.candidate.kernels:
            mappings = {
                (mapping.block, mapping.machine_ordinal, mapping.kind)
                for mapping in kernel.mappings
            }
            missing = []
            for block in kernel.blocks:
                key = (block.block_id, len(block.operations), "terminator")
                if key not in mappings:
                    missing.append(block.terminator[0])
            self.assertTrue(missing)
            self.assertEqual(set(missing), {"goto"})
            missing_by_kernel.append(len(missing))
        self.assertEqual(missing_by_kernel, [2, 4, 2, 2])

    def test_private_bundle_report_is_deterministic_and_structurally_exact(self) -> None:
        if self.bundle is None:
            self.skipTest("immutable first WP7C bundle is unavailable")
        first, first_root = forensics.analyze(self.bundle, self.emitter, self.admission)
        second, second_root = forensics.analyze(self.bundle, self.emitter, self.admission)
        self.assertEqual((first, first_root), (second, second_root))
        lines = first.decode().splitlines()
        self.assertEqual(len(lines), 280)
        self.assertEqual(
            [line for line in lines if line.startswith("candidate-rank\t")],
            [
                "candidate-rank\t01\tregister-resident-hot-state\t145291757\tstructural-dynamic-events\tnot-selected",
                "candidate-rank\t02\tloop-invariant-static-materialization\t10650200\tstructural-dynamic-events\tnot-selected",
                "candidate-rank\t03\tchecked-list-proof-hoisting\t4096000\tstructural-dynamic-events\tnot-selected",
                "candidate-rank\t04\tneutral-arithmetic-erasure\t1638400\tstructural-dynamic-events\tnot-selected",
            ],
        )
        kernel_rows = [line.split("\t") for line in lines if line.startswith("kernel\t")]
        self.assertEqual(len(kernel_rows), 4)
        self.assertEqual([row[10] for row in kernel_rows], ["608"] * 4)
        self.assertEqual([row[13] for row in kernel_rows], ["77"] * 4)
        self.assertEqual([row[7] for row in kernel_rows], [
            "17204168", "22406362", "15565768", "19661768"
        ])
        self.assertIn("threshold-candidate\tfail", lines)
        self.assertIn("claim-status\tnot-admitted", lines)

    def test_measured_artifact_mutation_fails_closed(self) -> None:
        artifacts = list(self._artifacts())
        changed = bytearray(artifacts[0])
        changed[-1] ^= 1
        artifacts[0] = bytes(changed)
        with self.assertRaises(forensics.ForensicsError):
            forensics.bind_artifact_chain(
                tuple(artifacts),
                self.candidate,
                self.admission.wp7b_admission.contract,
                self.admission.wp5e_admission.contract,
            )

    def test_wrong_oracle_and_step_budget_fail_closed(self) -> None:
        kernel = self.candidate.kernels[0]
        with self.assertRaises(forensics.ForensicsError):
            forensics.interpret_plan(kernel, 0)
        original = forensics.MAX_STEPS
        try:
            forensics.MAX_STEPS = 1
            with self.assertRaises(forensics.ForensicsError):
                forensics.interpret_plan(kernel, kernel.record.ordinal)
        finally:
            forensics.MAX_STEPS = original


if __name__ == "__main__":
    unittest.main()
