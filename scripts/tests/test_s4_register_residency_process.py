from __future__ import annotations

import importlib.util
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_process.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8g_process_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
process = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = process
SPEC.loader.exec_module(process)


class ResidencyProcessTests(unittest.TestCase):
    @staticmethod
    def _binary() -> Path | None:
        configured = os.environ.get("NAUX_S4_WP8G_BINARY")
        candidates = (
            Path(configured) if configured else None,
            ROOT / "target/debug/examples/naux_s4_register_residency_process",
            ROOT / "target/release/examples/naux_s4_register_residency_process",
        )
        for candidate in candidates:
            if candidate is not None and candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
        return None

    def _stdout(self) -> bytes:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP8G emitter is unavailable")
        process._validate_emitter_binary(binary)
        completed = process._run_emitter(binary.resolve())
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        return completed.stdout

    def test_repository_static_admission_is_deterministic(self) -> None:
        first = process.validate(ROOT)
        second = process.validate(ROOT)
        self.assertEqual(first, second)
        self.assertIn(b"claim-status\tuntimed-parity-only\n", first.static_report)
        self.assertIn(b"timing-status\tforbidden\n", first.static_report)

    def test_candidate_reconstructs_exactly_and_deterministically(self) -> None:
        raw = self._stdout()
        contract = process.parse_contract(
            ROOT / "distribution/s4-performance/WP8G-PROCESS.tsv"
        )
        first = process.parse_candidate(raw, contract)
        second = process.parse_candidate(raw, contract)
        self.assertEqual(first, second)
        self.assertEqual(len(first.kernels), 4)
        for kernel in first.kernels:
            self.assertEqual(kernel.elf[:4], b"\x7fELF")
            self.assertNotIn(struct.pack("<q", kernel.record.oracle), kernel.process)

    def test_two_fresh_process_passes_match_checksum_and_work_state(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP8G emitter is unavailable")
        report, candidate, results = process.replay(process.validate(ROOT), binary)
        self.assertEqual(len(candidate.kernels), 4)
        self.assertEqual(len(results), 8)
        self.assertEqual({result.pass_number for result in results}, {1, 2})
        self.assertTrue(all(result.inner == 16_384 and result.owner == 0 for result in results))
        self.assertIn(b"mode\tuntimed-fresh-process-replay\n", report)

    def test_candidate_target_and_elf_mutations_fail_closed(self) -> None:
        raw = self._stdout()
        contract = process.parse_contract(
            ROOT / "distribution/s4-performance/WP8G-PROCESS.tsv"
        )
        mutations = (
            raw.replace(b"candidate-target-hex\t01\t55", b"candidate-target-hex\t01\t54", 1),
            raw.replace(b"target-hex\t02\t55", b"target-hex\t02\t54", 1),
            raw.replace(b"elf-hex\t03\t7f", b"elf-hex\t03\t7e", 1),
            raw.replace(b"\t50\t16384\t", b"\t51\t16384\t", 1),
        )
        for mutation in mutations:
            with self.subTest(prefix=mutation[:24]):
                with self.assertRaises(process.ProcessReplayError):
                    process.parse_candidate(mutation, contract)

    def test_preexecution_hash_drift_stops_before_subprocess(self) -> None:
        contract = process.parse_contract(
            ROOT / "distribution/s4-performance/WP8G-PROCESS.tsv"
        )
        kernel = process.parse_candidate(self._stdout(), contract).kernels[0]
        with tempfile.TemporaryDirectory(prefix="naux-wp8g-preexec-") as directory:
            path = Path(directory) / "artifact"
            path.write_bytes(kernel.elf + b"drift")
            path.chmod(0o700)
            with mock.patch.object(
                process.subprocess,
                "run",
                side_effect=AssertionError("process must not start"),
            ):
                with self.assertRaisesRegex(
                    process.ProcessReplayError, "exact pre-execution admission"
                ):
                    process._run_process_image(path, kernel.record.elf_hash)

    def test_physical_guard_rejects_wrong_promoted_counter_bound(self) -> None:
        contract = process.parse_contract(
            ROOT / "distribution/s4-performance/WP8G-PROCESS.tsv"
        )
        kernel = process.parse_candidate(self._stdout(), contract).kernels[0]
        mutated = bytearray(kernel.elf)
        instruction = b"\x49\xb8" + (16_384).to_bytes(8, "little")
        instruction_offset = kernel.process.find(
            instruction, kernel.record.verifier_offset
        )
        self.assertNotEqual(instruction_offset, -1)
        immediate = kernel.record.target_offset + instruction_offset + 2
        self.assertEqual(
            mutated[immediate : immediate + 8], (16_384).to_bytes(8, "little")
        )
        mutated[immediate : immediate + 8] = (16_385).to_bytes(8, "little")
        payload = bytes(mutated)
        with tempfile.TemporaryDirectory(prefix="naux-wp8g-r12-guard-") as directory:
            path = Path(directory) / "artifact"
            process._write_exact_image(path, payload)
            completed = process._run_process_image(path, process._sha256(payload))
        self.assertEqual(completed.returncode, 70)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")

    def test_result_protocol_rejects_wrong_owner_and_trailing_output(self) -> None:
        record = process.parse_contract(
            ROOT / "distribution/s4-performance/WP8G-PROCESS.tsv"
        ).records[0]
        good = process.RESULT_STRUCT.pack(
            process.RESULT_MAGIC,
            record.ordinal,
            record.oracle,
            record.expected_outer,
            record.expected_inner,
            0,
        )
        completed = process.subprocess.CompletedProcess(["artifact"], 0, good, b"")
        self.assertEqual(process._parse_result(completed, record, 1).checksum, record.oracle)
        for payload in (
            process.RESULT_STRUCT.pack(
                process.RESULT_MAGIC,
                record.ordinal,
                record.oracle,
                record.expected_outer,
                record.expected_inner,
                1,
            ),
            good + b"x",
        ):
            with self.assertRaises(process.ProcessReplayError):
                process._parse_result(
                    process.subprocess.CompletedProcess(["artifact"], 0, payload, b""),
                    record,
                    1,
                )


if __name__ == "__main__":
    unittest.main()
