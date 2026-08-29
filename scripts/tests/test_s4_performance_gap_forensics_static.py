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
SCRIPT = ROOT / "scripts/s4_performance_gap_forensics.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_performance_gap_forensics_static", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
forensics = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = forensics
SPEC.loader.exec_module(forensics)


class S4PerformanceGapForensicsStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode())

    def test_static_admission_is_deterministic_and_preserves_rejection(self) -> None:
        first = forensics.validate(ROOT)
        second = forensics.validate(ROOT)
        self.assertEqual(first, second)
        text = first.report.decode()
        self.assertIn("mode\tstatic-no-bundle-no-clock-no-execution\n", text)
        self.assertIn("threshold-candidate\tfail\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)

    def test_default_validation_cannot_reach_explicit_analysis(self) -> None:
        with mock.patch.object(forensics, "analyze", side_effect=AssertionError("analysis")):
            forensics.validate(ROOT)

    def test_coherently_resealed_threshold_mutation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8a-contract-") as directory:
            path = Path(directory) / "WP8A-FORENSICS.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP8A-FORENSICS.tsv", path)
            path.write_text(path.read_text().replace("threshold-candidate\tfail", "threshold-candidate\tpass", 1))
            self._reseal(path, forensics.CONTRACT_DOMAIN)
            with self.assertRaises(forensics.ForensicsError):
                forensics.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = forensics.parse_contract(ROOT / "distribution/s4-performance/WP8A-FORENSICS.tsv")
        authority = forensics.parse_authority(
            ROOT / "distribution/s4-performance/WP8A-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8a-files-") as directory:
            copied = Path(directory)
            for relative in forensics.EXPECTED_FILES:
                target = copied / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            target = copied / "distribution/s4-performance/WP8A-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(forensics.ForensicsError):
                forensics._verify_files(copied, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP8A-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(forensics.ForensicsError):
                forensics._verify_files(copied, authority)

    def test_hosted_workflow_never_consumes_the_private_bundle(self) -> None:
        workflow = (ROOT / ".github/workflows/s4-performance-gap-forensics.yml").read_text()
        self.assertNotIn("--bundle", workflow)
        self.assertIn("test_s4_performance_gap_forensics_replay", workflow)


if __name__ == "__main__":
    unittest.main()
