#!/usr/bin/env python3

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
SCRIPT = ROOT / "scripts/s4_residual_timing.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_residual_timing", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
timing = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = timing
SPEC.loader.exec_module(timing)


class S4ResidualTimingTests(unittest.TestCase):
    @staticmethod
    def _binary() -> Path | None:
        configured = os.environ.get("NAUX_S4_RESIDUAL_TIMING_BINARY")
        candidates = (
            Path(configured) if configured else None,
            ROOT / "target/debug/examples/naux_s4_residual_timing",
            ROOT / "target/release/examples/naux_s4_residual_timing",
            Path("/tmp/naux-wp7b-build/debug/examples/naux_s4_residual_timing"),
        )
        for candidate in candidates:
            if candidate is not None and candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
        return None

    def _stdout(self) -> bytes:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP7B emitter is unavailable")
        timing._validate_emitter_binary(binary)
        completed = timing._run_emitter(binary.resolve())
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        return completed.stdout

    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(
            body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode()
        )

    def test_repository_static_admission_is_deterministic_and_untimed(self) -> None:
        first = timing.validate(ROOT)
        second = timing.validate(ROOT)
        self.assertEqual(first, second)
        text = first.static_report.decode()
        self.assertIn("status\tnaux-timing-carrier-structurally-admitted\n", text)
        self.assertIn("execution-status\tforbidden\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)
        self.assertIn("clock-reads\t2\n", text)

    def test_candidate_reconstructs_exactly_without_execution(self) -> None:
        raw = self._stdout()
        admission = timing.validate(ROOT)
        first = timing.parse_candidate(raw, admission.contract)
        second = timing.parse_candidate(raw, admission.contract)
        self.assertEqual(first, second)
        self.assertEqual(len(first.kernels), 4)
        for kernel in first.kernels:
            self.assertEqual(
                kernel.elf[kernel.record.target_offset :], kernel.target
            )
            self.assertEqual(timing._sha256(kernel.target), kernel.record.target_hash)

    def test_replay_is_deterministic_and_still_executes_no_generated_image(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP7B emitter is unavailable")
        admission = timing.validate(ROOT)
        first_report, first = timing.replay(admission, binary)
        second_report, second = timing.replay(admission, binary)
        self.assertEqual(first_report, second_report)
        self.assertEqual(first, second)
        self.assertIn(b"mode\tindependent-byte-replay-no-execution\n", first_report)

    def test_owner_cleanup_precedes_serialized_naux_role_identity(self) -> None:
        raw = self._stdout()
        contract = timing.parse_contract(
            ROOT / "distribution/s4-performance/WP7B-CARRIER.tsv"
        )
        candidate = timing.parse_candidate(raw, contract)
        cleanup_check = b"\x48\x85\xf6\x0f\x85"
        role_identity = (
            b"\x49\xb8"
            + timing.RESULT_OWNER.to_bytes(8, "little")
            + b"\x4c\x89\x44\x24"
            + bytes((timing.OWNER_OFFSET,))
        )
        for kernel in candidate.kernels:
            startup = kernel.elf[timing.ELF_ENTRY_OFFSET : kernel.record.target_offset]
            self.assertIn(cleanup_check, startup)
            self.assertIn(role_identity, startup)
            self.assertLess(startup.index(cleanup_check), startup.index(role_identity))

    def test_target_elf_and_receipt_mutations_fail_closed(self) -> None:
        raw = self._stdout()
        contract = timing.parse_contract(
            ROOT / "distribution/s4-performance/WP7B-CARRIER.tsv"
        )
        receipt = next(
            line for line in raw.splitlines() if line.startswith(b"kernel\t01\t")
        )
        receipt_fields = receipt.split(b"\t")
        receipt_fields[7] = str(int(receipt_fields[7]) + 1).encode("ascii")
        drifted_receipt = b"\t".join(receipt_fields)
        mutations = (
            raw.replace(b"target-hex\t01\t55", b"target-hex\t01\t54", 1),
            raw.replace(b"elf-hex\t02\t7f", b"elf-hex\t02\t7e", 1),
            raw.replace(receipt, drifted_receipt, 1),
            raw.replace(
                b"verification\tregenerated-no-execution",
                b"runtime-ns\t1",
                1,
            ),
        )
        for mutation in mutations:
            with self.subTest(prefix=mutation[:32]):
                with self.assertRaises(timing.TimingReplayError):
                    timing.parse_candidate(mutation, contract)

    def test_contract_mutation_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7b-contract-") as directory:
            path = Path(directory) / "WP7B-CARRIER.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP7B-CARRIER.tsv", path)
            path.write_text(
                path.read_text().replace("clock-reads\t2", "clock-reads\t1", 1)
            )
            self._reseal(path, timing.CONTRACT_DOMAIN)
            with self.assertRaises(timing.TimingReplayError):
                timing.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = timing.parse_contract(
            ROOT / "distribution/s4-performance/WP7B-CARRIER.tsv"
        )
        authority = timing.parse_authority(
            ROOT / "distribution/s4-performance/WP7B-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp7b-files-") as directory:
            root = Path(directory)
            for relative in timing.EXPECTED_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = root / "distribution/s4-performance/WP7B-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(timing.TimingReplayError):
                timing._verify_files(root, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP7B-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(timing.TimingReplayError):
                timing._verify_files(root, authority)

    def test_emitter_symlink_and_generated_image_are_rejected(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed WP7B emitter is unavailable")
        candidate = timing.parse_candidate(
            self._stdout(),
            timing.parse_contract(
                ROOT / "distribution/s4-performance/WP7B-CARRIER.tsv"
            ),
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp7b-emitter-") as directory:
            root = Path(directory)
            link = root / "naux_s4_residual_timing"
            link.symlink_to(binary.resolve())
            with self.assertRaisesRegex(timing.TimingReplayError, "regular executable"):
                timing._validate_emitter_binary(link)
            link.unlink()
            link.write_bytes(candidate.kernels[0].elf)
            link.chmod(0o700)
            with self.assertRaisesRegex(timing.TimingReplayError, "generated timing image"):
                timing._validate_emitter_binary(link)

    def test_generic_support_has_no_kernel_dispatch_or_oracle_literal(self) -> None:
        support = (
            ROOT / "naux-lang/examples/support/s4_residual_timing_elf.rs"
        ).read_text()
        for _ordinal, name, oracle in timing.wp7a.KERNELS:
            self.assertNotIn(name, support)
            self.assertNotIn(str(oracle), support)
            self.assertNotIn(f"{oracle:_}", support)


if __name__ == "__main__":
    unittest.main()
