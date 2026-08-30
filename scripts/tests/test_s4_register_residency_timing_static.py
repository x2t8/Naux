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
SCRIPT = ROOT / "scripts/s4_register_residency_timing.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8j_timing_static_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
carrier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = carrier
SPEC.loader.exec_module(carrier)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() == carrier.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8J static tests require the current Apache-2.0 surface",
)
class RegisterResidencyTimingStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode())

    def test_static_admission_is_deterministic_and_claim_free(self) -> None:
        first = carrier.validate(ROOT)
        second = carrier.validate(ROOT)
        self.assertEqual(first, second)
        text = first.static_report.decode()
        self.assertIn("status\tcandidate-timing-carrier-structurally-admitted\n", text)
        self.assertIn("mode\tstatic-no-host-no-clock-no-execution\n", text)
        self.assertIn("execution-status\tforbidden\n", text)
        self.assertIn("role-owner\t4\n", text)

    def test_default_validation_cannot_run_emitter_or_parse_candidate(self) -> None:
        with (
            mock.patch.object(carrier, "_run_emitter", side_effect=AssertionError("execution")),
            mock.patch.object(carrier, "parse_candidate", side_effect=AssertionError("replay")),
        ):
            carrier.validate(ROOT)

    def test_contract_mutation_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8j-contract-") as directory_name:
            path = Path(directory_name) / "WP8J-CARRIER.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP8J-CARRIER.tsv", path)
            path.write_text(path.read_text().replace("role-owner\t4", "role-owner\t3", 1))
            self._reseal(path, carrier.CONTRACT_DOMAIN)
            with self.assertRaises(carrier.CandidateTimingError):
                carrier.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = carrier.parse_contract(ROOT / "distribution/s4-performance/WP8J-CARRIER.tsv")
        authority = carrier.parse_authority(
            ROOT / "distribution/s4-performance/WP8J-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8j-files-") as directory_name:
            copied = Path(directory_name)
            for relative in carrier.EXPECTED_FILES:
                destination = copied / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = copied / "distribution/s4-performance/WP8J-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(carrier.CandidateTimingError):
                carrier._verify_files(copied, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP8J-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(carrier.CandidateTimingError):
                carrier._verify_files(copied, authority)

    def test_workflow_builds_and_replays_only_the_reviewed_emitter(self) -> None:
        workflow = (ROOT / ".github/workflows/s4-register-residency-timing.yml").read_text()
        self.assertIn("naux_s4_register_residency_timing", workflow)
        self.assertNotIn("--acquire", workflow)
        self.assertNotIn("taskset", workflow)


if __name__ == "__main__":
    unittest.main()
