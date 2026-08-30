from __future__ import annotations

import hashlib
import importlib.util
import sys
import tempfile
import types
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts.tests import test_s4_register_residency_paired_evidence_replay as evidence_fixture


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_paired_threshold.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8o_paired_threshold_replay_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
threshold = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = threshold
SPEC.loader.exec_module(threshold)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == threshold.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


def _bundle(parent: Path) -> tuple[Path, object, object]:
    fixture = evidence_fixture.RegisterResidencyPairedEvidenceReplayTests
    return fixture._bundle(parent)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8O replay tests require the current Apache-2.0 surface",
)
class RegisterResidencyPairedThresholdReplayTests(unittest.TestCase):
    @staticmethod
    def _admission(evidence_admission: object) -> object:
        return types.SimpleNamespace(
            contract=types.SimpleNamespace(seal="d" * 64),
            authority=types.SimpleNamespace(seal="e" * 64),
            evidence=evidence_admission,
        )

    @staticmethod
    def _comparison(**changes: object) -> object:
        base = threshold.wp8n.KernelComparison(
            "01",
            "sum-dense",
            1,
            2,
            120_000_000,
            110_000_000,
            30,
            21_000,
            20_000,
            -1_000,
            700,
            1,
            660,
            1,
            -40,
            1,
            22,
            0,
            8,
            21,
            20,
        )
        return replace(base, **changes)

    def test_exact_bundle_passes_all_gates_but_never_admits_claim(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8o-pass-") as directory_name:
            bundle, evidence_admission, retained = _bundle(Path(directory_name))
            admission = self._admission(evidence_admission)
            with mock.patch.object(
                threshold.wp8n.wp8m.wp8k,
                "parse_retained_host",
                return_value=retained,
            ):
                result = threshold.evaluate_bundle(bundle, admission)
        self.assertTrue(result.threshold_pass)
        self.assertEqual(sum(item.kernel_pass for item in result.decisions), 4)
        self.assertIn(b"threshold-candidate\tpass\n", result.report)
        self.assertIn(b"claim-status\tnot-admitted\n", result.report)
        self.assertIn(b"claim-authority\trequired-not-admitted\n", result.report)

    def test_exact_sign_tail_boundary_is_22_of_30(self) -> None:
        passing = threshold.decide_kernel(self._comparison(candidate_wins=22, candidate_losses=8))
        failing = threshold.decide_kernel(self._comparison(candidate_wins=21, candidate_losses=9))
        self.assertEqual((passing.sign_tail_num, passing.sign_tail_den), (8656937, 1073741824))
        self.assertTrue(passing.sign_pass)
        self.assertFalse(failing.sign_pass)

    def test_ties_reduce_effective_coverage_and_cannot_be_hidden(self) -> None:
        decision = threshold.decide_kernel(
            self._comparison(candidate_wins=23, ties=7, candidate_losses=0)
        )
        self.assertEqual(decision.effective_pairs, 23)
        self.assertFalse(decision.coverage_pass)
        self.assertFalse(decision.kernel_pass)

    def test_speedup_boundary_uses_exact_cross_products(self) -> None:
        passing = threshold.decide_kernel(
            self._comparison(total_ratio_num=21, total_ratio_den=20)
        )
        failing = threshold.decide_kernel(
            self._comparison(total_ratio_num=104, total_ratio_den=100)
        )
        self.assertTrue(passing.magnitude_pass)
        self.assertFalse(failing.magnitude_pass)

    def test_nonnegative_paired_median_fails_direction(self) -> None:
        zero = threshold.decide_kernel(
            self._comparison(delta_median_num=0, delta_median_den=1)
        )
        positive = threshold.decide_kernel(
            self._comparison(delta_median_num=1, delta_median_den=2)
        )
        self.assertFalse(zero.direction_pass)
        self.assertFalse(positive.direction_pass)

    def test_one_failed_kernel_fails_the_family_candidate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8o-family-") as directory_name:
            bundle, evidence_admission, retained = _bundle(Path(directory_name))
            admission = self._admission(evidence_admission)
            with mock.patch.object(
                threshold.wp8n.wp8m.wp8k,
                "parse_retained_host",
                return_value=retained,
            ):
                replay = threshold.wp8n.replay_bundle(bundle, evidence_admission)
            comparisons = list(replay.session.comparisons)
            comparisons[0] = replace(
                comparisons[0], total_ratio_num=1, total_ratio_den=1
            )
            replay = replace(
                replay, session=replace(replay.session, comparisons=tuple(comparisons))
            )
            decisions, report, _root, passed = threshold._candidate_report(
                admission, replay
            )
        self.assertFalse(decisions[0].magnitude_pass)
        self.assertFalse(passed)
        self.assertIn(b"passing-kernels\t3\n", report)
        self.assertIn(b"threshold-candidate\tfail\n", report)

    def test_malformed_pair_partition_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            threshold.PairedThresholdError, "comparison shape drifted"
        ):
            threshold.decide_kernel(
                self._comparison(candidate_wins=22, ties=1, candidate_losses=8)
            )


if __name__ == "__main__":
    unittest.main()
