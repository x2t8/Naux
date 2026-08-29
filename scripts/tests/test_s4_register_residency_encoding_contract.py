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
SCRIPT = ROOT / "scripts/s4_register_residency_encoding_contract.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_register_residency_encoding_contract_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
encoding = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = encoding
SPEC.loader.exec_module(encoding)

APACHE_LICENSE_SHA256 = (
    "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
)


class S4RegisterResidencyEncodingContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() != APACHE_LICENSE_SHA256:
            raise unittest.SkipTest("WP8D tests require the current Apache surface")

    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode())

    def test_static_authority_is_deterministic_and_nonclaiming(self) -> None:
        first = encoding.validate(ROOT)
        second = encoding.validate(ROOT)
        self.assertEqual(first, second)
        self.assertEqual(first.contract.seal, encoding.CONTRACT_SEAL)
        self.assertEqual(len(first.contract.kernels), 4)
        self.assertEqual(len(first.authority.files), 6)
        text = first.report.decode()
        self.assertIn("implementation-status\tabsent\n", text)
        self.assertIn("candidate-bytes-status\tabsent\n", text)
        self.assertIn("native-execution-status\tforbidden\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)

    def test_exact_templates_and_width_equations_are_closed(self) -> None:
        contract = encoding.parse_contract(
            ROOT / "distribution/s4-performance/WP8D-ENCODING-CONTRACT.tsv"
        )
        self.assertEqual({row[5] for row in encoding.EXPECTED_TEMPLATES}, {"7"})
        self.assertEqual([row[17] for row in contract.kernels], ["972", "1167", "929", "1043"])
        self.assertEqual([row[18] for row in contract.kernels], ["21", "21", "21", "28"])
        for row in contract.kernels:
            reads, writes, sites = int(row[8]), int(row[9]), int(row[10])
            self.assertEqual(sites, reads + writes)
            self.assertEqual(int(row[11]), sites * 14)
            self.assertEqual(int(row[12]), sites * 7)
            self.assertLess(int(row[17]), int(row[16]))

    def test_coherently_resealed_contract_mutation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8d-contract-") as directory:
            path = Path(directory) / "WP8D.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP8D-ENCODING-CONTRACT.tsv", path)
            path.write_text(path.read_text().replace("candidate-bytes-status\tabsent", "candidate-bytes-status\tpresent", 1))
            self._reseal(path, encoding.CONTRACT_DOMAIN)
            with self.assertRaises(encoding.EncodingContractError):
                encoding.parse_contract(path)

    def test_bound_file_mutation_and_symlink_fail_closed(self) -> None:
        contract = encoding.parse_contract(
            ROOT / "distribution/s4-performance/WP8D-ENCODING-CONTRACT.tsv"
        )
        bound = encoding.parse_authority(
            ROOT / "distribution/s4-performance/WP8D-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8d-files-") as directory:
            copied = Path(directory)
            for relative in encoding.EXPECTED_FILES:
                target = copied / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            target = copied / "distribution/s4-performance/WP8D-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(encoding.EncodingContractError):
                encoding._verify_files(copied, bound)
            shutil.copy2(ROOT / "distribution/s4-performance/WP8D-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(encoding.EncodingContractError):
                encoding._verify_files(copied, bound)

    def test_authority_binds_no_candidate_or_executable_artifact(self) -> None:
        admission = encoding.validate(ROOT)
        forbidden = (".bin", ".elf", ".o", ".so", ".exe")
        self.assertFalse(any(record.path.endswith(forbidden) for record in admission.authority.files))
        self.assertFalse(any(record.path.endswith(".rs") for record in admission.authority.files))


if __name__ == "__main__":
    unittest.main()
