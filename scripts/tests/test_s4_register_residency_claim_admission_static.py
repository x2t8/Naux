from __future__ import annotations

import hashlib
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_claim_admission.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8p_claim_static_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
claim = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = claim
SPEC.loader.exec_module(claim)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == claim.wp8o.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8P static tests require the current Apache-2.0 surface",
)
class RegisterResidencyClaimAdmissionStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode())

    def test_static_report_is_deterministic_and_never_evaluates_a_bundle(self) -> None:
        with mock.patch.object(
            claim.wp8o, "evaluate_bundle", side_effect=AssertionError("bundle")
        ):
            first = claim.validate(ROOT)
            second = claim.validate(ROOT)
        self.assertEqual(first, second)
        text = first.report.decode()
        self.assertIn(
            "protocol-status\tregister-residency-claim-protocol-structurally-admitted\n",
            text,
        )
        self.assertIn("admission-status\tblocked\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)
        self.assertIn("blockers\t4\n", text)

    def test_contract_mutation_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8p-contract-") as directory_name:
            path = Path(directory_name) / "WP8P-CLAIM.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP8P-CLAIM.tsv", path)
            path.write_text(
                path.read_text().replace(
                    "language-wide-naux-speedup\tforbidden",
                    "language-wide-naux-speedup\tpermitted",
                    1,
                )
            )
            self._reseal(path, claim.CONTRACT_DOMAIN)
            with self.assertRaises(claim.ClaimAdmissionError):
                claim.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = claim.parse_contract(
            ROOT / "distribution/s4-performance/WP8P-CLAIM.tsv"
        )
        authority = claim.parse_authority(
            ROOT / "distribution/s4-performance/WP8P-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8p-files-") as directory_name:
            copied = Path(directory_name)
            for relative in claim.EXPECTED_FILES:
                destination = copied / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = copied / "distribution/s4-performance/WP8P-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(claim.ClaimAdmissionError):
                claim._verify_files(copied, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP8P-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(claim.ClaimAdmissionError):
                claim._verify_files(copied, authority)

    def test_workflow_runs_only_static_refusal_tests(self) -> None:
        workflow = (
            ROOT / ".github/workflows/s4-register-residency-claim-admission.yml"
        ).read_text()
        self.assertNotIn("--" + "bundle", workflow)
        self.assertNotIn("taskset", workflow)
        self.assertNotIn("curl ", workflow)


if __name__ == "__main__":
    unittest.main()
