from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_timing.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8j_timing_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
carrier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = carrier
SPEC.loader.exec_module(carrier)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() == carrier.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8J replay tests require the current Apache-2.0 surface",
)
class RegisterResidencyTimingReplayTests(unittest.TestCase):
    @staticmethod
    def _binary() -> Path | None:
        configured = os.environ.get("NAUX_S4_REGISTER_RESIDENCY_TIMING_BINARY")
        candidates = (
            Path(configured) if configured else None,
            ROOT / "target/debug/examples/naux_s4_register_residency_timing",
            ROOT / "target/release/examples/naux_s4_register_residency_timing",
        )
        for candidate in candidates:
            if candidate is not None and candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
        return None

    def _stdout(self) -> bytes:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP8J emitter is unavailable")
        completed = carrier._run_emitter(binary.resolve())
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        return completed.stdout

    def test_replay_reconstructs_four_exact_unexecuted_images(self) -> None:
        admission = carrier.validate(ROOT)
        report, first = carrier.replay(admission, self._binary_or_skip())
        second = carrier.parse_candidate(self._stdout(), admission.contract)
        self.assertEqual(first, second)
        self.assertEqual(len(first.kernels), 4)
        self.assertIn(b"mode\tindependent-byte-replay-no-execution\n", report)
        self.assertIn(b"claim-status\tnot-admitted\n", report)
        for kernel in first.kernels:
            self.assertEqual(kernel.elf[kernel.record.target_offset:], kernel.target)

    def test_candidate_targets_equal_the_wp8h_role_targets(self) -> None:
        admission = carrier.validate(ROOT)
        candidate = carrier.parse_candidate(self._stdout(), admission.contract)
        for kernel, parent in zip(candidate.kernels, admission.role.contract.artifacts, strict=True):
            self.assertEqual(carrier._sha256(kernel.target), parent.target_hash)
            self.assertEqual(kernel.record.oracle, parent.oracle)

    def test_role_owner_changes_once_after_target_cleanup(self) -> None:
        candidate = carrier.parse_candidate(
            self._stdout(), carrier.parse_contract(ROOT / "distribution/s4-performance/WP8J-CARRIER.tsv")
        )
        baseline = carrier._owner_store(carrier.BASELINE_OWNER)
        role_four = carrier._owner_store(carrier.CANDIDATE_OWNER)
        cleanup = b"\x48\x85\xf6\x0f\x85"
        for kernel in candidate.kernels:
            startup = kernel.elf[carrier.wp7b.ELF_ENTRY_OFFSET:kernel.record.target_offset]
            self.assertNotIn(baseline, startup)
            self.assertEqual(startup.count(role_four), 1)
            self.assertLess(startup.index(cleanup), startup.index(role_four))

    def test_payload_and_receipt_mutations_fail_closed(self) -> None:
        raw = self._stdout()
        contract = carrier.parse_contract(ROOT / "distribution/s4-performance/WP8J-CARRIER.tsv")
        mutations = (
            raw.replace(b"target-hex\t01\t55", b"target-hex\t01\t54", 1),
            raw.replace(b"elf-hex\t02\t7f", b"elf-hex\t02\t7e", 1),
            raw.replace(b"\t345\t608\n", b"\t344\t608\n", 1),
            raw.replace(b"verification\tregenerated-no-execution", b"runtime-ns\t1", 1),
        )
        for mutation in mutations:
            with self.subTest(prefix=mutation[:32]):
                with self.assertRaises(carrier.CandidateTimingError):
                    carrier.parse_candidate(mutation, contract)

    def test_emitter_symlink_and_generated_image_are_rejected(self) -> None:
        binary = self._binary_or_skip()
        candidate = carrier.parse_candidate(
            self._stdout(), carrier.parse_contract(ROOT / "distribution/s4-performance/WP8J-CARRIER.tsv")
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8j-emitter-") as directory_name:
            directory = Path(directory_name)
            link = directory / "naux_s4_register_residency_timing"
            link.symlink_to(binary.resolve())
            with self.assertRaisesRegex(carrier.CandidateTimingError, "regular executable"):
                carrier._validate_emitter_binary(link)
            link.unlink()
            link.write_bytes(candidate.kernels[0].elf)
            link.chmod(0o700)
            with self.assertRaisesRegex(carrier.CandidateTimingError, "generated timing image"):
                carrier._validate_emitter_binary(link)

    def _binary_or_skip(self) -> Path:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP8J emitter is unavailable")
        return binary


if __name__ == "__main__":
    unittest.main()
