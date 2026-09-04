from __future__ import annotations

import hashlib
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_register_residency_public_protocol.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("s4_wp8q_public_protocol_static_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
receipt = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = receipt
SPEC.loader.exec_module(receipt)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == receipt.wp8p.wp8o.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8Q static tests require the current Apache-2.0 surface",
)
class RegisterResidencyPublicProtocolStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        seal = hashlib.sha256(domain + body).hexdigest()
        path.write_bytes(body + f"seal\t{seal}\n".encode())

    def test_report_is_deterministic_and_retains_three_blockers(self) -> None:
        first = receipt.validate(ROOT)
        second = receipt.validate(ROOT)
        self.assertEqual(first, second)
        text = first.report.decode()
        self.assertIn("public-protocol-gate\tclosed\n", text)
        self.assertIn(f"tracked-commit\t{receipt.TRACKED_COMMIT}\n", text)
        self.assertIn("admission-status\tblocked\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)
        self.assertIn("blockers\t3\n", text)

    def test_coherently_resealed_run_mutation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8q-contract-") as name:
            path = Path(name) / "WP8Q-PUBLIC-PROTOCOL.tsv"
            shutil.copy2(
                ROOT / "distribution/s4-performance/WP8Q-PUBLIC-PROTOCOL.tsv",
                path,
            )
            path.write_text(
                path.read_text().replace("33785721821", "33785721822", 1)
            )
            self._reseal(path, receipt.CONTRACT_DOMAIN)
            with self.assertRaises(receipt.PublicProtocolError):
                receipt.parse_contract(path)

    def test_bound_file_drift_and_symlink_fail_closed(self) -> None:
        contract = receipt.parse_contract(
            ROOT / "distribution/s4-performance/WP8Q-PUBLIC-PROTOCOL.tsv"
        )
        authority = receipt.parse_authority(
            ROOT / "distribution/s4-performance/WP8Q-AUTHORITY.tsv",
            contract.seal,
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8q-files-") as name:
            copied = Path(name)
            for relative in receipt.EXPECTED_FILES:
                destination = copied / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = copied / "distribution/s4-performance/WP8Q-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(receipt.PublicProtocolError):
                receipt._verify_files(copied, authority)
            shutil.copy2(
                ROOT / "distribution/s4-performance/WP8Q-NONCLAIMS.md", target
            )
            copied_target = target.with_suffix(".copy")
            target.rename(copied_target)
            target.symlink_to(copied_target.name)
            with self.assertRaises(receipt.PublicProtocolError):
                receipt._verify_files(copied, authority)

    def test_workflow_is_offline_and_static(self) -> None:
        workflow = (
            ROOT / ".github/workflows/s4-register-residency-public-protocol.yml"
        ).read_text()
        self.assertNotIn("curl ", workflow)
        self.assertNotIn("workflow_run", workflow)
        self.assertNotIn("repository_dispatch", workflow)


if __name__ == "__main__":
    unittest.main()
