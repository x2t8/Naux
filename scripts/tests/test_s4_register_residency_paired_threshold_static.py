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
SCRIPT = ROOT / "scripts/s4_register_residency_paired_threshold.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8o_paired_threshold_static_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
threshold = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = threshold
SPEC.loader.exec_module(threshold)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == threshold.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8O static tests require the current Apache-2.0 surface",
)
class RegisterResidencyPairedThresholdStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode())

    def test_static_admission_is_deterministic_and_never_evaluates_a_bundle(self) -> None:
        with (
            mock.patch.object(
                threshold, "evaluate_bundle", side_effect=AssertionError("bundle")
            ),
            mock.patch.object(
                threshold.wp8n, "replay_bundle", side_effect=AssertionError("replay")
            ),
        ):
            first = threshold.validate(ROOT)
            second = threshold.validate(ROOT)
        self.assertEqual(first, second)
        text = first.static_report.decode()
        self.assertIn("status\tpaired-threshold-structurally-admitted\n", text)
        self.assertIn("mode\tstatic-no-bundle-no-host-no-clock-no-execution\n", text)
        self.assertIn("threshold-status\tlaw-admitted-result-unavailable\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)

    def test_contract_mutation_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8o-contract-") as directory_name:
            path = Path(directory_name) / "WP8O-PAIRED-THRESHOLD.tsv"
            shutil.copy2(
                ROOT / "distribution/s4-performance/WP8O-PAIRED-THRESHOLD.tsv", path
            )
            path.write_text(path.read_text().replace("21/20", "1/1", 1))
            self._reseal(path, threshold.CONTRACT_DOMAIN)
            with self.assertRaises(threshold.PairedThresholdError):
                threshold.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = threshold.parse_contract(
            ROOT / "distribution/s4-performance/WP8O-PAIRED-THRESHOLD.tsv"
        )
        authority = threshold.parse_authority(
            ROOT / "distribution/s4-performance/WP8O-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8o-files-") as directory_name:
            copied = Path(directory_name)
            for relative in threshold.EXPECTED_FILES:
                destination = copied / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = copied / "distribution/s4-performance/WP8O-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(threshold.PairedThresholdError):
                threshold._verify_files(copied, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP8O-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(threshold.PairedThresholdError):
                threshold._verify_files(copied, authority)

    def test_hosted_workflow_is_static_only(self) -> None:
        workflow = (
            ROOT / ".github/workflows/s4-register-residency-paired-threshold.yml"
        ).read_text()
        self.assertNotIn("--bundle", workflow)
        self.assertNotIn("taskset", workflow)
        self.assertNotIn("--acquire", workflow)


if __name__ == "__main__":
    unittest.main()
