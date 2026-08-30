from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_candidate_authority.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8e_authority_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
wp8e = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = wp8e
SPEC.loader.exec_module(wp8e)


class CandidateAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        raw = os.environ.get("NAUX_S4_WP8E_REPORT")
        if not raw:
            raise unittest.SkipTest("NAUX_S4_WP8E_REPORT is required")
        cls.report_path = Path(raw)
        cls.raw = cls.report_path.read_bytes()

    def test_static_authority_and_exact_report_are_accepted(self) -> None:
        authority, report, admission, root = wp8e.validate(ROOT, self.report_path)
        self.assertEqual(len(authority.files), len(wp8e.EXPECTED_FILES))
        self.assertEqual(report.root, wp8e.CANDIDATE_ROOT)
        self.assertEqual(report.sha256, wp8e.CANDIDATE_SHA256)
        self.assertIn(root.encode(), admission)

    def test_candidate_byte_mutation_is_rejected(self) -> None:
        mutated = bytearray(self.raw)
        marker = b"target-hex\t01\t"
        offset = mutated.index(marker) + len(marker)
        mutated[offset] = ord("4") if mutated[offset] != ord("4") else ord("5")
        with self.assertRaises(wp8e.CandidateAuthorityError):
            wp8e.parse_candidate_report(bytes(mutated))

    def test_candidate_root_mutation_is_rejected(self) -> None:
        mutated = self.raw.replace(
            wp8e.CANDIDATE_ROOT.encode(), b"0" * 64, 1
        )
        with self.assertRaises(wp8e.CandidateAuthorityError):
            wp8e.parse_candidate_report(mutated)

    def test_truncated_or_noncanonical_report_is_rejected(self) -> None:
        for raw in (self.raw[:-1], self.raw + b"\n", self.raw.replace(b"\n", b"\r\n", 1)):
            with self.subTest(length=len(raw)):
                with self.assertRaises(wp8e.CandidateAuthorityError):
                    wp8e.parse_candidate_report(raw)

    def test_contract_seal_mutation_is_rejected(self) -> None:
        contract = ROOT / "distribution/s4-performance/WP8E-CANDIDATE-ENCODING.tsv"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "contract.tsv"
            target.write_bytes(contract.read_bytes().replace(b"function-bytes-only", b"function-bytez-only", 1))
            with self.assertRaises(wp8e.CandidateAuthorityError):
                wp8e.parse_contract(target)


if __name__ == "__main__":
    unittest.main()
