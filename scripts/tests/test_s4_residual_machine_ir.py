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
SCRIPT = ROOT / "scripts/s4_residual_machine_ir.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_residual_machine_ir", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
machine = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = machine
SPEC.loader.exec_module(machine)


class S4ResidualMachineIrTests(unittest.TestCase):
    @staticmethod
    def _binary() -> Path | None:
        configured = os.environ.get("NAUX_S4_RESIDUAL_MACHINE_IR_BINARY")
        candidates = (
            Path(configured) if configured else None,
            ROOT / "target/release/examples/naux_s4_residual_machine_ir",
            Path("/tmp/naux-codex-target/release/examples/naux_s4_residual_machine_ir"),
            Path("/tmp/naux-codex-target/debug/examples/naux_s4_residual_machine_ir"),
        )
        for candidate in candidates:
            if candidate is not None and candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate.resolve()
        return None

    def _stdout(self) -> bytes:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed residual Machine IR binary is unavailable")
        completed = machine._run(binary)
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
        first = machine.validate(ROOT)
        second = machine.validate(ROOT)
        self.assertEqual(first, second)
        text = first.report.decode()
        self.assertIn("machine-status\tresidual-machine-ir-admitted\n", text)
        self.assertIn("elf-status\tunavailable\n", text)
        self.assertIn("timing-status\tforbidden\n", text)
        self.assertEqual(text.count("blocker\t"), 3)

    def test_exact_candidate_replays_twice(self) -> None:
        binary = self._binary()
        if binary is None:
            self.skipTest("reviewed residual Machine IR binary is unavailable")
        admission = machine.validate(ROOT)
        report, candidate = machine.replay(ROOT, admission, binary)
        self.assertIn(b"mode\tuntimed-machine-replay\n", report)
        self.assertIn(b"replays\t2\n", report)
        self.assertEqual(len(candidate.kernels), 4)

    def test_candidate_machine_mapping_and_type_mutations_are_rejected(self) -> None:
        original = self._stdout()
        contract = machine.parse_contract(ROOT / "distribution/s4-performance/WP5C-MACHINE-IR.tsv")
        mutations = (
            original.replace(b"97d8699e", b"07d8699e", 1),
            original.replace(b"i64-add\tr15:i64", b"i64-sub\tr15:i64", 1),
            original.replace(b"load-slot\tr5:i64\ts3", b"load-slot\tr5:i64\ts2", 1),
            original.replace(b"mapping\t01\t13\t1\t3\tterminator", b"mapping\t01\t13\t2\t3\tterminator", 1),
            original.replace(b"branch\tr7:bool\tb2\tb6", b"branch\tr7:bool\tb3\tb6", 1),
            original.replace(b"release-owned-list\ts2", b"release-owned-list\ts3", 1),
        )
        for mutation in mutations:
            with self.subTest(prefix=mutation[:28]):
                with self.assertRaises(machine.MachineIrError):
                    machine.parse_candidate(mutation, contract)

    def test_candidate_rejects_timing_and_noncanonical_text(self) -> None:
        original = self._stdout()
        contract = machine.parse_contract(ROOT / "distribution/s4-performance/WP5C-MACHINE-IR.tsv")
        mutations = (
            original.replace(b"verification\t", b"runtime-ns\t1\nverification\t", 1),
            original.rstrip(b"\n"),
            original.replace(b"\n", b"\r\n"),
            original + b"trailing\trow\n",
        )
        for mutation in mutations:
            with self.assertRaises(machine.MachineIrError):
                machine.parse_candidate(mutation, contract)

    def test_contract_mutation_fails_even_after_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp5c-contract-") as directory:
            path = Path(directory) / "WP5C-MACHINE-IR.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP5C-MACHINE-IR.tsv", path)
            path.write_text(path.read_text().replace("elf-status\tunavailable", "elf-status\tready", 1))
            self._reseal(path, machine.CONTRACT_DOMAIN)
            with self.assertRaises(machine.MachineIrError):
                machine.parse_contract(path)

    def test_bound_file_drift_and_symlink_are_rejected(self) -> None:
        contract = machine.parse_contract(ROOT / "distribution/s4-performance/WP5C-MACHINE-IR.tsv")
        authority = machine.parse_authority(
            ROOT / "distribution/s4-performance/WP5C-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp5c-files-") as directory:
            root = Path(directory)
            for relative in machine.EXPECTED_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = root / "distribution/s4-performance/WP5C-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(machine.MachineIrError):
                machine._verify_files(root, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP5C-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(machine.MachineIrError):
                machine._verify_files(root, authority)

    def test_generic_lowering_rejects_kernel_dispatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp5c-source-") as directory:
            root = Path(directory)
            for relative in machine.EXPECTED_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            support = root / "naux-lang/examples/support/s4_residual_machine_ir.rs"
            support.write_text(support.read_text() + "\n// sum-dense special case\n")
            with self.assertRaises(machine.MachineIrError):
                machine._verify_source_boundary(root)

    def test_process_invocation_is_fixed_argv_without_shell(self) -> None:
        completed = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch.object(subprocess, "run", return_value=completed) as run:
            result = machine._run(Path("/bin/true"))
        self.assertEqual(result.returncode, 0)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/bin/true"])
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["input"], b"")


if __name__ == "__main__":
    unittest.main()
