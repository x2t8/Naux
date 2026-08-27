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
SCRIPT = ROOT / "scripts/s4_measurement_evidence.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_measurement_evidence_static", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)


class S4MeasurementEvidenceStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(
            body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode()
        )

    def test_static_law_is_deterministic_and_admits_no_measurement(self) -> None:
        first = evidence.validate(ROOT)
        second = evidence.validate(ROOT)
        self.assertEqual(first, second)
        text = first.static_report.decode()
        self.assertIn("law-status\tevidence-law-admitted\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)
        self.assertIn("timing-status\tforbidden\n", text)
        self.assertIn("samples-required\t360\n", text)

    def test_contract_mutation_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp7a-contract-") as directory:
            path = Path(directory) / "WP7A-EVIDENCE.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP7A-EVIDENCE.tsv", path)
            path.write_text(path.read_text().replace("ordered-complete-no-drop-no-retry", "drop-outliers", 1))
            self._reseal(path, evidence.CONTRACT_DOMAIN)
            with self.assertRaises(evidence.EvidenceError):
                evidence.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = evidence.parse_contract(
            ROOT / "distribution/s4-performance/WP7A-EVIDENCE.tsv"
        )
        authority = evidence.parse_authority(
            ROOT / "distribution/s4-performance/WP7A-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp7a-files-") as directory:
            root = Path(directory)
            for relative in evidence.EXPECTED_FILES:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = root / "distribution/s4-performance/WP7A-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(evidence.EvidenceError):
                evidence._verify_files(root, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP7A-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(evidence.EvidenceError):
                evidence._verify_files(root, authority)

    def test_source_contains_no_clock_or_process_acquisition(self) -> None:
        source = SCRIPT.read_text()
        forbidden = (
            "import " + "time",
            "import " + "subprocess",
            "." + "monotonic(",
            "." + "perf_counter(",
            "." + "clock_gettime(",
        )
        self.assertFalse(any(token in source for token in forbidden))


if __name__ == "__main__":
    unittest.main()
