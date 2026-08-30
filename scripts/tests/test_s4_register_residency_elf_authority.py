from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_elf_authority.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8f_authority_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
wp8f = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = wp8f
SPEC.loader.exec_module(wp8f)


class ElfAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        raw = os.environ.get("NAUX_S4_WP8F_REPORT")
        if not raw:
            raise unittest.SkipTest("NAUX_S4_WP8F_REPORT is required")
        cls.report_path = Path(raw)
        cls.raw = cls.report_path.read_bytes()

    def test_static_authority_and_exact_report_are_accepted(self) -> None:
        authority, report, admission, root = wp8f.validate(ROOT, self.report_path)
        self.assertEqual(len(authority.files), len(wp8f.EXPECTED_FILES))
        self.assertEqual(report.root, wp8f.ELF_REPORT_ROOT)
        self.assertEqual(report.sha256, wp8f.ELF_REPORT_SHA256)
        self.assertIn(root.encode(), admission)

    def test_header_target_and_image_mutations_are_rejected(self) -> None:
        marker = b"elf-hex\t01\t"
        start = self.raw.index(marker) + len(marker)
        for byte_offset in (0, 68, 256, 272 + 17):
            mutated = bytearray(self.raw)
            nibble = start + byte_offset * 2
            mutated[nibble] = ord("4") if mutated[nibble] != ord("4") else ord("5")
            with self.subTest(byte_offset=byte_offset):
                with self.assertRaises(wp8f.ElfAuthorityError):
                    wp8f.parse_elf_report(bytes(mutated))

    def test_report_root_or_document_identity_mutation_is_rejected(self) -> None:
        for mutated in (
            self.raw.replace(wp8f.ELF_REPORT_ROOT.encode(), b"0" * 64, 1),
            self.raw.replace(b"report-hex-only", b"report-heq-only", 1),
        ):
            with self.assertRaises(wp8f.ElfAuthorityError):
                wp8f.parse_elf_report(mutated)

    def test_truncated_or_noncanonical_report_is_rejected(self) -> None:
        for raw in (self.raw[:-1], self.raw + b"\n", self.raw.replace(b"\n", b"\r\n", 1)):
            with self.subTest(length=len(raw)):
                with self.assertRaises(wp8f.ElfAuthorityError):
                    wp8f.parse_elf_report(raw)

    def test_contract_seal_mutation_is_rejected(self) -> None:
        contract = ROOT / "distribution/s4-performance/WP8F-ELF64-CONTRACT.tsv"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "contract.tsv"
            target.write_bytes(
                contract.read_bytes().replace(b"report-hex-only", b"report-heq-only", 1)
            )
            with self.assertRaises(wp8f.ElfAuthorityError):
                wp8f.parse_contract(target)


if __name__ == "__main__":
    unittest.main()
