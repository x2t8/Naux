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
SCRIPT = ROOT / "scripts/s4_claim_admission.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_claim_admission_static", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
admission = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = admission
SPEC.loader.exec_module(admission)


class S4ClaimAdmissionStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(
            body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode()
        )

    def test_static_report_is_deterministic_blocked_and_claim_free(self) -> None:
        first = admission.validate(ROOT)
        second = admission.validate(ROOT)
        self.assertEqual(first, second)
        text = first.report.decode()
        self.assertIn("protocol-status\tclaim-protocol-structurally-admitted\n", text)
        self.assertIn("admission-status\tblocked\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)
        self.assertIn("blockers\t4\n", text)

    def test_claim_class_widening_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7e-contract-") as directory:
            path = Path(directory) / "WP7E-CLAIM.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP7E-CLAIM.tsv", path)
            path.write_text(
                path.read_text().replace(
                    "language-wide-performance-leadership\tforbidden",
                    "language-wide-performance-leadership\tpermitted",
                    1,
                )
            )
            self._reseal(path, admission.CONTRACT_DOMAIN)
            with self.assertRaises(admission.ClaimAdmissionError):
                admission.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = admission.parse_contract(
            ROOT / "distribution/s4-performance/WP7E-CLAIM.tsv"
        )
        authority = admission.parse_authority(
            ROOT / "distribution/s4-performance/WP7E-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp7e-files-") as directory:
            copied = Path(directory)
            for relative in admission.EXPECTED_FILES:
                destination = copied / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = copied / "distribution/s4-performance/WP7E-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(admission.ClaimAdmissionError):
                admission._verify_files(copied, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP7E-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(admission.ClaimAdmissionError):
                admission._verify_files(copied, authority)


if __name__ == "__main__":
    unittest.main()
