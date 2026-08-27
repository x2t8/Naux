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
SCRIPT = ROOT / "scripts/s4_c_timing_carriers.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_c_timing_carriers", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
carriers = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = carriers
SPEC.loader.exec_module(carriers)


class S4CTimingCarrierTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(
            body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode()
        )

    def test_static_admission_is_deterministic_and_executes_nothing(self) -> None:
        first = carriers.validate(ROOT)
        second = carriers.validate(ROOT)
        self.assertEqual(first, second)
        text = first.report.decode()
        self.assertIn("status\tc-timing-carriers-structurally-admitted\n", text)
        self.assertIn("execution-status\tforbidden\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)
        self.assertIn("roles\t2\n", text)
        self.assertIn("kernels\t4\n", text)

    def test_all_derived_sources_reconstruct_byte_exactly(self) -> None:
        contract = carriers.parse_contract(
            ROOT / "distribution/s4-performance/C-TIMING-CARRIER.tsv"
        )
        for record in contract.kernels:
            parent = (ROOT / record.parent_path).read_bytes()
            derived = (ROOT / record.derived_path).read_bytes()
            self.assertEqual(carriers.derive_source(parent, record), derived)
            self.assertEqual(carriers._sha256(parent), record.parent_hash)
            self.assertEqual(carriers._sha256(derived), record.derived_hash)

    def test_contract_semantic_mutation_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7b-c-contract-") as directory:
            path = Path(directory) / "C-TIMING-CARRIER.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/C-TIMING-CARRIER.tsv", path)
            path.write_text(path.read_text().replace("clock-reads\t2", "clock-reads\t3", 1))
            self._reseal(path, carriers.CONTRACT_DOMAIN)
            with self.assertRaises(carriers.CCarrierError):
                carriers.parse_contract(path)

    def test_derived_mutation_fails_exact_transformation(self) -> None:
        contract = carriers.parse_contract(
            ROOT / "distribution/s4-performance/C-TIMING-CARRIER.tsv"
        )
        record = contract.kernels[0]
        parent = (ROOT / record.parent_path).read_bytes()
        mutation = (ROOT / record.derived_path).read_bytes().replace(
            b"sum += values[i];", b"sum -= values[i];", 1
        )
        self.assertNotEqual(carriers.derive_source(parent, record), mutation)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = carriers.parse_contract(
            ROOT / "distribution/s4-performance/C-TIMING-CARRIER.tsv"
        )
        authority = carriers.parse_authority(
            ROOT / "distribution/s4-performance/C-TIMING-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp7b-c-files-") as directory:
            root = Path(directory)
            for relative in carriers.EXPECTED_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = root / "benchmarks/s4/c/timing_carrier.h"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(carriers.CCarrierError):
                carriers._verify_files(root, authority)
            shutil.copy2(ROOT / "benchmarks/s4/c/timing_carrier.h", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(carriers.CCarrierError):
                carriers._verify_files(root, authority)

    def test_non_executing_compile_audit_when_compiler_is_available(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None or os.uname().machine != "x86_64":
            self.skipTest("Linux x86-64 C compiler is unavailable")
        admission = carriers.validate(ROOT)
        first, first_root = carriers.compile_audit(ROOT, admission, compiler)
        second, second_root = carriers.compile_audit(ROOT, admission, compiler)
        self.assertEqual(first, second)
        self.assertEqual(first_root, second_root)
        self.assertIn(b"mode\tcompile-audit-no-execution\n", first)
        self.assertIn(b"compiler-output-executed\tno\n", first)
        self.assertEqual(first.count(b"build\t"), 8)


if __name__ == "__main__":
    unittest.main()
