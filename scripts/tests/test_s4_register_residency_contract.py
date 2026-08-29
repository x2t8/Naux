#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_contract.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_register_residency_contract_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
residency = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = residency
SPEC.loader.exec_module(residency)

APACHE_LICENSE_SHA256 = (
    "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
)


class S4RegisterResidencyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() != APACHE_LICENSE_SHA256:
            raise unittest.SkipTest("WP8B tests require the current Apache surface")

    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode())

    def test_static_admission_is_deterministic_and_nonclaiming(self) -> None:
        first = residency.validate(ROOT)
        second = residency.validate(ROOT)
        self.assertEqual(first, second)
        text = first.report.decode()
        self.assertIn("implementation-status\tabsent\n", text)
        self.assertIn("target-byte-status\tunchanged\n", text)
        self.assertIn("measurement-status\tforbidden\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)

    def test_exact_selection_is_one_i64_r12_slot_per_kernel(self) -> None:
        contract = residency.parse_contract(
            ROOT / "distribution/s4-performance/WP8B-REGISTER-RESIDENCY.tsv"
        )
        self.assertEqual(len(contract.kernels), 4)
        self.assertEqual({row[4] for row in contract.kernels}, {"i64"})
        self.assertEqual({row[5] for row in contract.kernels}, {"r12"})
        self.assertEqual(sum(int(row[8]) for row in contract.kernels), 13_926_800)
        self.assertTrue(all(int(row[10]) == int(row[9]) - 1 for row in contract.kernels))

    def test_coherently_resealed_selection_mutation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8b-contract-") as directory:
            path = Path(directory) / "WP8B.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP8B-REGISTER-RESIDENCY.tsv", path)
            path.write_text(path.read_text().replace("candidate-rank\t1", "candidate-rank\t2", 1))
            self._reseal(path, residency.CONTRACT_DOMAIN)
            with self.assertRaises(residency.ResidencyError):
                residency.parse_contract(path)

    def test_bound_file_mutation_and_symlink_fail_closed(self) -> None:
        contract = residency.parse_contract(
            ROOT / "distribution/s4-performance/WP8B-REGISTER-RESIDENCY.tsv"
        )
        authority = residency.parse_authority(
            ROOT / "distribution/s4-performance/WP8B-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8b-files-") as directory:
            copied = Path(directory)
            for relative in residency.EXPECTED_FILES:
                target = copied / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            target = copied / "distribution/s4-performance/WP8B-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(residency.ResidencyError):
                residency._verify_files(copied, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP8B-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(residency.ResidencyError):
                residency._verify_files(copied, authority)

    def test_contract_binds_no_implementation_or_measurement_file(self) -> None:
        contract = residency.parse_contract(
            ROOT / "distribution/s4-performance/WP8B-REGISTER-RESIDENCY.tsv"
        )
        authority = residency.parse_authority(
            ROOT / "distribution/s4-performance/WP8B-AUTHORITY.tsv", contract.seal
        )
        self.assertFalse(any(record.path.startswith("naux-lang/") for record in authority.files))
        self.assertFalse(any("benchmark" in record.path for record in authority.files))


if __name__ == "__main__":
    unittest.main()
