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
SCRIPT = ROOT / "scripts/s4_register_residency_plan_authority.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_register_residency_plan_authority_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
authority = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = authority
SPEC.loader.exec_module(authority)

APACHE_LICENSE_SHA256 = (
    "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
)


class S4RegisterResidencyPlanAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() != APACHE_LICENSE_SHA256:
            raise unittest.SkipTest("WP8C tests require the current Apache surface")

    @staticmethod
    def _reseal(path: Path, domain: bytes, label: str = "seal") -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(body + f"{label}\t{hashlib.sha256(domain + body).hexdigest()}\n".encode())

    @staticmethod
    def _report_path() -> Path:
        raw = os.environ.get("NAUX_S4_WP8C_REPORT")
        if not raw:
            raise unittest.SkipTest("reviewed WP8C emitter report is unavailable")
        return Path(raw)

    def test_static_authority_is_deterministic_and_nonclaiming(self) -> None:
        first = authority.validate_static(ROOT)
        second = authority.validate_static(ROOT)
        self.assertEqual(first, second)
        contract, bound = first
        self.assertEqual(contract.seal, authority.CONTRACT_SEAL)
        self.assertEqual(len(contract.kernels), 4)
        self.assertEqual(len(bound.files), 8)

    def test_contract_binds_exact_one_hot_r12_plan(self) -> None:
        contract = authority.parse_contract(
            ROOT / "distribution/s4-performance/WP8C-CANDIDATE-PLAN.tsv"
        )
        self.assertEqual({row[5] for row in contract.kernels}, {"s5", "s6"})
        self.assertEqual({row[6] for row in contract.kernels}, {"i64"})
        self.assertEqual({row[7] for row in contract.kernels}, {"r12"})
        self.assertEqual([row[13] for row in contract.kernels], [
            "17204168", "22406362", "15565768", "19661768"
        ])
        self.assertTrue(all(row[14:19] == ("0", "1", "1", "0", "r12-restored") for row in contract.kernels))

    def test_coherently_resealed_contract_mutation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8c-contract-") as directory:
            path = Path(directory) / "WP8C.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP8C-CANDIDATE-PLAN.tsv", path)
            path.write_text(path.read_text().replace("replay-step-limit\t30000000", "replay-step-limit\t30000001", 1))
            self._reseal(path, authority.CONTRACT_DOMAIN)
            with self.assertRaises(authority.PlanAuthorityError):
                authority.parse_contract(path)

    def test_bound_file_mutation_and_symlink_fail_closed(self) -> None:
        contract = authority.parse_contract(
            ROOT / "distribution/s4-performance/WP8C-CANDIDATE-PLAN.tsv"
        )
        bound = authority.parse_authority(
            ROOT / "distribution/s4-performance/WP8C-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8c-files-") as directory:
            copied = Path(directory)
            for relative in authority.EXPECTED_FILES:
                target = copied / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            target = copied / "distribution/s4-performance/WP8C-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(authority.PlanAuthorityError):
                authority._verify_files(copied, bound)
            shutil.copy2(ROOT / "distribution/s4-performance/WP8C-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(authority.PlanAuthorityError):
                authority._verify_files(copied, bound)

    def test_candidate_report_replays_exactly(self) -> None:
        report_path = self._report_path()
        admission = authority.validate(ROOT, report_path)
        self.assertEqual(admission.plan.root, authority.PLAN_REPORT_ROOT)
        self.assertEqual(admission.plan.sha256, authority.PLAN_REPORT_SHA256)
        text = admission.report.decode()
        self.assertIn("status\tcandidate-plan-semantically-admitted\n", text)
        self.assertIn("encoding-status\tforbidden\n", text)
        self.assertIn("measurement-status\tforbidden\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)

    def test_coherently_resealed_report_mutation_fails_closed(self) -> None:
        source = self._report_path()
        contract = authority.parse_contract(
            ROOT / "distribution/s4-performance/WP8C-CANDIDATE-PLAN.tsv"
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8c-report-") as directory:
            path = Path(directory) / "report.tsv"
            shutil.copy2(source, path)
            path.write_text(path.read_text().replace("6710476800", "6710476801", 1))
            self._reseal(path, authority.PLAN_REPORT_DOMAIN, "report-root")
            with self.assertRaises(authority.PlanAuthorityError):
                authority.parse_plan_report(path, contract)

    def test_report_symlink_fails_closed(self) -> None:
        source = self._report_path()
        contract = authority.parse_contract(
            ROOT / "distribution/s4-performance/WP8C-CANDIDATE-PLAN.tsv"
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8c-link-") as directory:
            link = Path(directory) / "report.tsv"
            link.symlink_to(source)
            with self.assertRaises(authority.PlanAuthorityError):
                authority.parse_plan_report(link, contract)

    def test_authority_binds_no_encoding_or_measurement_artifact(self) -> None:
        contract = authority.parse_contract(
            ROOT / "distribution/s4-performance/WP8C-CANDIDATE-PLAN.tsv"
        )
        bound = authority.parse_authority(
            ROOT / "distribution/s4-performance/WP8C-AUTHORITY.tsv", contract.seal
        )
        self.assertFalse(any("benchmark" in record.path for record in bound.files))
        self.assertFalse(any("residual_x64_elf" in record.path for record in bound.files))


if __name__ == "__main__":
    unittest.main()
