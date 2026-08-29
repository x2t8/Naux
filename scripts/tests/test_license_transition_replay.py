#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/license_transition.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("license_transition_replay", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
transition = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = transition
SPEC.loader.exec_module(transition)


class LicenseTransitionReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() != transition.APACHE_HASH:
            raise unittest.SkipTest("LT1 tests run only against the current Apache surface")

    def test_historical_snapshot_replays_old_authorities(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-lt1-view-parent-") as directory:
            view = Path(directory) / "pre-apache"
            transition.materialize_historical(ROOT, view)
            transition.replay_historical(view)
            self.assertFalse((view / "actions-runner").exists())
            self.assertFalse((view / "target").exists())
            for *_fields, relative in transition.TRANSITIONS:
                self.assertEqual(
                    (view / relative).read_bytes(),
                    (ROOT / "distribution/license-transition/pre-apache" / relative).read_bytes(),
                )

    def test_current_and_historical_emitters_have_identical_targets_when_configured(self) -> None:
        historical_root = os.environ.get("NAUX_LT1_HISTORICAL_ROOT")
        current_binary = os.environ.get("NAUX_LT1_CURRENT_EMITTER")
        historical_binary = os.environ.get("NAUX_LT1_HISTORICAL_EMITTER")
        if not all((historical_root, current_binary, historical_binary)):
            self.skipTest("LT1 dual-emitter replay is not configured")
        admission = transition.validate(ROOT)
        report, _root = transition.replay(
            ROOT,
            admission,
            Path(historical_root),
            Path(current_binary),
            Path(historical_binary),
        )
        self.assertIn(b"historical-authority-status\treplayed\n", report)
        self.assertIn(b"current-target-identity\tidentical\n", report)
        self.assertIn(b"claim-status\tnot-admitted\n", report)


if __name__ == "__main__":
    unittest.main()
