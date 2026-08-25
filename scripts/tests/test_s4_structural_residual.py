#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_structural_residual.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_structural_residual", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
residual = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = residual
SPEC.loader.exec_module(residual)


class S4StructuralResidualTests(unittest.TestCase):
    @staticmethod
    def _binary() -> Path | None:
        configured = os.environ.get("NAUX_S4_STRUCTURAL_RESIDUAL_BINARY")
        candidates = (
            Path(configured) if configured else None,
            ROOT / "target/release/examples/naux_s4_structural_residual",
            Path("/tmp/naux-codex-target/release/examples/naux_s4_structural_residual"),
            Path("/tmp/naux-codex-target/debug/examples/naux_s4_structural_residual"),
        )
        for candidate in candidates:
            if candidate is not None and candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate.resolve()
        return None

    def _stdout(self) -> bytes:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed structural-residual binary is unavailable")
        completed = residual._run(binary)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        return completed.stdout

    @staticmethod
    def _reseal(path: Path, domain: bytes) -> str:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        seal = hashlib.sha256(domain + body).hexdigest()
        path.write_bytes(body + f"seal\t{seal}\n".encode())
        return seal

    def test_repository_static_admission_is_deterministic(self) -> None:
        first = residual.validate(ROOT)
        second = residual.validate(ROOT)
        self.assertEqual(first, second)
        text = first.report.decode()
        self.assertIn("residual-status\tstructural-residual-admitted\n", text)
        self.assertIn("native-status\tunavailable\n", text)
        self.assertIn("timing-status\tforbidden\n", text)
        self.assertEqual(text.count("blocker\t"), 3)

    def test_exact_candidate_replays_twice(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed structural-residual binary is unavailable")
        admission = residual.validate(ROOT)
        report, candidate = residual.replay(ROOT, admission, binary)
        self.assertIn(b"mode\tuntimed-structural-replay\n", report)
        self.assertIn(b"replays\t2\n", report)
        self.assertEqual(len(candidate.kernels), 4)

    def test_candidate_hash_and_instruction_mutations_are_rejected(self) -> None:
        original = self._stdout()
        contract = residual.parse_contract(ROOT / "distribution/s4-performance/WP5B-RESIDUAL.tsv")
        mutations = (
            original.replace(b"bed3ac17", b"0ed3ac17", 1),
            original.replace(b"op\t01\t0038\tjump\t18", b"op\t01\t0038\tjump\t19", 1),
            original.replace(b"witness\t01\t4\t45", b"witness\t01\t5\t45", 1),
            original.replace(b"witness\t01\t4\t45", b"witness\t01\t9999\t45", 1),
            original.replace(b"list-load", b"list-store", 1),
        )
        for mutation in mutations:
            with self.subTest(prefix=mutation[:24]):
                with self.assertRaises(residual.ResidualError):
                    residual.parse_candidate(mutation, contract)

    def test_candidate_rejects_timing_and_noncanonical_text(self) -> None:
        original = self._stdout()
        contract = residual.parse_contract(ROOT / "distribution/s4-performance/WP5B-RESIDUAL.tsv")
        mutations = (
            original.replace(b"verification\t", b"runtime-ns\t1\nverification\t", 1),
            original.rstrip(b"\n"),
            original.replace(b"\n", b"\r\n"),
            original + b"trailing\trow\n",
        )
        for mutation in mutations:
            with self.assertRaises(residual.ResidualError):
                residual.parse_candidate(mutation, contract)

    def test_contract_mutation_fails_even_after_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp5b-contract-") as directory:
            path = Path(directory) / "WP5B-RESIDUAL.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP5B-RESIDUAL.tsv", path)
            path.write_text(path.read_text().replace("native-status\tunavailable", "native-status\tready", 1))
            self._reseal(path, residual.CONTRACT_DOMAIN)
            with self.assertRaises(residual.ResidualError):
                residual.parse_contract(path)

    def test_bound_file_drift_and_symlink_are_rejected(self) -> None:
        contract = residual.parse_contract(ROOT / "distribution/s4-performance/WP5B-RESIDUAL.tsv")
        authority = residual.parse_authority(
            ROOT / "distribution/s4-performance/WP5B-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp5b-files-") as directory:
            root = Path(directory)
            for relative in residual.EXPECTED_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = root / "distribution/s4-performance/WP5B-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(residual.ResidualError):
                residual._verify_files(root, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP5B-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(residual.ResidualError):
                residual._verify_files(root, authority)

    def test_generic_lowering_rejects_kernel_dispatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp5b-source-") as directory:
            root = Path(directory)
            for relative in residual.EXPECTED_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            support = root / "naux-lang/examples/support/s4_whole_program_residual.rs"
            support.write_text(support.read_text() + "\n// sum-dense special case\n")
            with self.assertRaises(residual.ResidualError):
                residual._verify_source_boundary(root)

    def test_process_invocation_is_fixed_argv_without_shell(self) -> None:
        completed = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch.object(subprocess, "run", return_value=completed) as run:
            result = residual._run(Path("/bin/true"))
        self.assertEqual(result.returncode, 0)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/bin/true"])
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["input"], b"")


if __name__ == "__main__":
    unittest.main()
