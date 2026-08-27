#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_threshold_evaluator.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_threshold_evaluator_static", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
evaluator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evaluator
SPEC.loader.exec_module(evaluator)


class S4ThresholdEvaluatorStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(
            body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode()
        )

    def test_static_admission_is_deterministic_and_never_admits_a_claim(self) -> None:
        first = evaluator.validate(ROOT)
        second = evaluator.validate(ROOT)
        self.assertEqual(first, second)
        text = first.report.decode()
        self.assertIn("status\tthreshold-evaluator-structurally-admitted\n", text)
        self.assertIn("mode\tstatic-no-host-no-clock-no-execution\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)
        self.assertIn("blockers\t3\n", text)

    def test_default_validation_cannot_reach_bundle_replay(self) -> None:
        with mock.patch.object(
            evaluator, "replay_bundle", side_effect=AssertionError("bundle replay")
        ):
            evaluator.validate(ROOT)

    def test_contract_mutation_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7d-contract-") as directory:
            path = Path(directory) / "WP7D-THRESHOLD.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP7D-THRESHOLD.tsv", path)
            path.write_text(
                path.read_text().replace(
                    "same-kernel-must-pass-both-thresholds",
                    "different-kernels-may-pass-thresholds",
                    1,
                )
            )
            self._reseal(path, evaluator.CONTRACT_DOMAIN)
            with self.assertRaises(evaluator.ThresholdError):
                evaluator.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = evaluator.parse_contract(
            ROOT / "distribution/s4-performance/WP7D-THRESHOLD.tsv"
        )
        authority = evaluator.parse_authority(
            ROOT / "distribution/s4-performance/WP7D-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp7d-files-") as directory:
            copied = Path(directory)
            for relative in evaluator.EXPECTED_FILES:
                destination = copied / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = copied / "distribution/s4-performance/WP7D-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(evaluator.ThresholdError):
                evaluator._verify_files(copied, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP7D-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(evaluator.ThresholdError):
                evaluator._verify_files(copied, authority)

    def test_hosted_workflow_remains_static_only(self) -> None:
        workflow = (ROOT / ".github/workflows/s4-threshold-evaluator.yml").read_text()
        self.assertNotIn("--bundle", workflow)
        self.assertIn("test_s4_threshold_evaluator_static", workflow)
        self.assertIn("test_s4_threshold_evaluator_replay", workflow)


if __name__ == "__main__":
    unittest.main()
