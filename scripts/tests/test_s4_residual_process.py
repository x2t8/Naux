#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residual_process.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_residual_process", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
process = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = process
SPEC.loader.exec_module(process)


class S4ResidualProcessTests(unittest.TestCase):
    @staticmethod
    def _binary() -> Path | None:
        configured = os.environ.get("NAUX_S4_RESIDUAL_PROCESS_BINARY")
        shared = Path(
            "/run/media/txuandev/New Volume/David Xuân Tools/Kali/"
            ".naux-codex-target"
        )
        candidates = (
            Path(configured) if configured else None,
            ROOT / "target/debug/examples/naux_s4_residual_process",
            ROOT / "target/release/examples/naux_s4_residual_process",
            shared / "debug/examples/naux_s4_residual_process",
            shared / "release/examples/naux_s4_residual_process",
            Path("/tmp/naux-codex-target/debug/examples/naux_s4_residual_process"),
        )
        for candidate in candidates:
            if candidate is not None and candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
        return None

    def _stdout(self) -> bytes:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP5E emitter is unavailable")
        process._validate_emitter_binary(binary)
        completed = process._run_emitter(binary.resolve())
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        return completed.stdout

    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode())

    def test_repository_static_admission_is_deterministic(self) -> None:
        first = process.validate(ROOT)
        second = process.validate(ROOT)
        self.assertEqual(first, second)
        text = first.static_report.decode()
        self.assertIn("status\tfresh-process-checksum-work-parity-admitted\n", text)
        self.assertIn("claim-status\tuntimed-parity-only\n", text)
        self.assertIn("timing-status\tforbidden\n", text)

    def test_candidate_reconstructs_exactly_and_deterministically(self) -> None:
        raw = self._stdout()
        contract = process.parse_contract(
            ROOT / "distribution/s4-performance/WP5E-PROCESS.tsv"
        )
        first = process.parse_candidate(raw, contract)
        second = process.parse_candidate(raw, contract)
        self.assertEqual(first, second)
        self.assertEqual(len(first.kernels), 4)
        for kernel in first.kernels:
            self.assertEqual(kernel.elf[:4], b"\x7fELF")
            self.assertNotIn(
                process.struct.pack("<q", kernel.record.oracle),
                kernel.process_target,
            )

    def test_two_fresh_process_passes_match_checksum_and_work(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP5E emitter is unavailable")
        admission = process.validate(ROOT)
        report, candidate, results = process.replay(admission, binary)
        self.assertEqual(len(candidate.kernels), 4)
        self.assertEqual(len(results), 8)
        self.assertEqual({result.pass_number for result in results}, {1, 2})
        self.assertTrue(all(result.owner == 0 for result in results))
        self.assertIn(b"mode\tuntimed-fresh-process-replay\n", report)
        self.assertIn(b"replays\t2\n", report)

    def test_candidate_target_and_elf_mutations_fail_closed(self) -> None:
        raw = self._stdout()
        contract = process.parse_contract(
            ROOT / "distribution/s4-performance/WP5E-PROCESS.tsv"
        )
        mutations = (
            raw.replace(b"target-hex\t01\t55", b"target-hex\t01\t54", 1),
            raw.replace(b"elf-hex\t02\t7f", b"elf-hex\t02\t7e", 1),
            raw.replace(b"\t50\t16384\t", b"\t51\t16384\t", 1),
            raw.replace(b"verification\tregenerated", b"runtime-ns\t1", 1),
        )
        for mutation in mutations:
            with self.subTest(prefix=mutation[:24]):
                with self.assertRaises(process.ProcessReplayError):
                    process.parse_candidate(mutation, contract)

    def test_contract_mutation_fails_even_after_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp5e-contract-") as directory:
            path = Path(directory) / "WP5E-PROCESS.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP5E-PROCESS.tsv", path)
            path.write_text(path.read_text().replace("timing-status\tforbidden", "timing-status\tready", 1))
            self._reseal(path, process.CONTRACT_DOMAIN)
            with self.assertRaises(process.ProcessReplayError):
                process.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = process.parse_contract(
            ROOT / "distribution/s4-performance/WP5E-PROCESS.tsv"
        )
        authority = process.parse_authority(
            ROOT / "distribution/s4-performance/WP5E-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp5e-files-") as directory:
            root = Path(directory)
            for relative in process.EXPECTED_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = root / "distribution/s4-performance/WP5E-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(process.ProcessReplayError):
                process._verify_files(root, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP5E-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(process.ProcessReplayError):
                process._verify_files(root, authority)

    def test_emitter_symlink_and_generated_image_are_rejected(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP5E emitter is unavailable")
        raw = self._stdout()
        contract = process.parse_contract(
            ROOT / "distribution/s4-performance/WP5E-PROCESS.tsv"
        )
        candidate = process.parse_candidate(raw, contract)
        with tempfile.TemporaryDirectory(prefix="naux-wp5e-emitter-") as directory:
            root = Path(directory)
            link = root / "naux_s4_residual_process"
            link.symlink_to(binary.resolve())
            with self.assertRaisesRegex(process.ProcessReplayError, "regular executable"):
                process._validate_emitter_binary(link)
            image = root / "naux_s4_residual_process"
            link.unlink()
            image.write_bytes(candidate.kernels[0].elf)
            image.chmod(0o700)
            with self.assertRaisesRegex(process.ProcessReplayError, "generated process image"):
                process._validate_emitter_binary(image)

    def test_preexecution_hash_drift_stops_before_subprocess(self) -> None:
        raw = self._stdout()
        contract = process.parse_contract(
            ROOT / "distribution/s4-performance/WP5E-PROCESS.tsv"
        )
        kernel = process.parse_candidate(raw, contract).kernels[0]
        with tempfile.TemporaryDirectory(prefix="naux-wp5e-preexec-") as directory:
            path = Path(directory) / "artifact"
            path.write_bytes(kernel.elf + b"drift")
            path.chmod(0o700)
            with mock.patch.object(
                process.subprocess,
                "run",
                side_effect=AssertionError("process must not start"),
            ):
                with self.assertRaisesRegex(
                    process.ProcessReplayError,
                    "exact pre-execution admission",
                ):
                    process._run_process_image(path, kernel.record.elf_hash)

    def test_physical_completion_guard_rejects_wrong_outer_bound(self) -> None:
        raw = self._stdout()
        contract = process.parse_contract(
            ROOT / "distribution/s4-performance/WP5E-PROCESS.tsv"
        )
        kernel = process.parse_candidate(raw, contract).kernels[0]
        mutated = bytearray(kernel.elf)
        immediate = (
            kernel.record.target_offset
            + kernel.record.verifier_offset
            + 16
        )
        self.assertEqual(mutated[immediate : immediate + 8], (50).to_bytes(8, "little"))
        mutated[immediate : immediate + 8] = (51).to_bytes(8, "little")
        payload = bytes(mutated)
        with tempfile.TemporaryDirectory(prefix="naux-wp5e-physical-guard-") as directory:
            path = Path(directory) / "artifact"
            process._write_exact_image(path, payload)
            completed = process._run_process_image(path, process._sha256(payload))
        self.assertEqual(completed.returncode, process.FAILURE_EXIT_CODE)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"")

    def test_result_protocol_rejects_wrong_owner_and_trailing_output(self) -> None:
        record = process.parse_contract(
            ROOT / "distribution/s4-performance/WP5E-PROCESS.tsv"
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
        mutations = (
            process.RESULT_STRUCT.pack(
                process.RESULT_MAGIC,
                record.ordinal,
                record.oracle,
                record.expected_outer,
                record.expected_inner,
                1,
            ),
            good + b"x",
        )
        for payload in mutations:
            with self.assertRaises(process.ProcessReplayError):
                process._parse_result(
                    process.subprocess.CompletedProcess(["artifact"], 0, payload, b""),
                    record,
                    1,
                )


if __name__ == "__main__":
    unittest.main()
