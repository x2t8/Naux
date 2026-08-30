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
SCRIPT = ROOT / "scripts/s4_register_residency_paired_evidence.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8n_paired_evidence_static_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = evidence
SPEC.loader.exec_module(evidence)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == evidence.wp8m.wp8k.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8N static tests require the current Apache-2.0 surface",
)
class RegisterResidencyPairedEvidenceStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode())

    def test_static_admission_is_deterministic_and_reads_no_bundle(self) -> None:
        with (
            mock.patch.object(evidence, "_bundle_directory", side_effect=AssertionError("bundle")),
            mock.patch.object(evidence, "parse_manifest", side_effect=AssertionError("manifest")),
            mock.patch.object(evidence, "parse_session", side_effect=AssertionError("clock")),
            mock.patch.object(evidence.wp8m.wp8k, "parse_retained_host", side_effect=AssertionError("host")),
        ):
            first = evidence.validate(ROOT)
            second = evidence.validate(ROOT)
        self.assertEqual(first, second)
        text = first.static_report.decode()
        self.assertIn("status\tpaired-evidence-replay-structurally-admitted\n", text)
        self.assertIn("mode\tstatic-no-bundle-no-host-no-clock-no-execution\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)

    def test_contract_mutation_fails_after_coherent_reseal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8n-contract-") as directory_name:
            path = Path(directory_name) / "WP8N-PAIRED-EVIDENCE.tsv"
            shutil.copy2(ROOT / "distribution/s4-performance/WP8N-PAIRED-EVIDENCE.tsv", path)
            path.write_text(path.read_text().replace("exact-integer-paired-reduction-no-float", "float-mean", 1))
            self._reseal(path, evidence.CONTRACT_DOMAIN)
            with self.assertRaises(evidence.PairedEvidenceError):
                evidence.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = evidence.parse_contract(
            ROOT / "distribution/s4-performance/WP8N-PAIRED-EVIDENCE.tsv"
        )
        authority = evidence.parse_authority(
            ROOT / "distribution/s4-performance/WP8N-AUTHORITY.tsv", contract.seal
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8n-files-") as directory_name:
            copied = Path(directory_name)
            for relative in evidence.EXPECTED_FILES:
                destination = copied / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = copied / "distribution/s4-performance/WP8N-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(evidence.PairedEvidenceError):
                evidence._verify_files(copied, authority)
            shutil.copy2(ROOT / "distribution/s4-performance/WP8N-NONCLAIMS.md", target)
            copy = target.with_suffix(".copy")
            target.rename(copy)
            target.symlink_to(copy.name)
            with self.assertRaises(evidence.PairedEvidenceError):
                evidence._verify_files(copied, authority)

    def test_hosted_workflow_cannot_replay_or_execute(self) -> None:
        workflow = (
            ROOT / ".github/workflows/s4-register-residency-paired-evidence.yml"
        ).read_text()
        self.assertNotIn("--bundle", workflow)
        self.assertNotIn("--acquire", workflow)
        self.assertNotIn("taskset", workflow)


if __name__ == "__main__":
    unittest.main()
