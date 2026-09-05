from __future__ import annotations

import contextlib
import hashlib
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import s4_register_residency_exact_claim as claim


CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == claim.wp8r.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8S static tests require the Apache-2.0 surface",
)
class RegisterResidencyExactClaimStaticTests(unittest.TestCase):
    @staticmethod
    def _reseal(path: Path, domain: bytes) -> None:
        lines = path.read_bytes().splitlines(keepends=True)
        body = b"".join(lines[:-1])
        path.write_bytes(
            body + f"seal\t{hashlib.sha256(domain + body).hexdigest()}\n".encode()
        )

    def test_static_report_is_deterministic_and_cannot_replay(self) -> None:
        with (
            mock.patch.object(
                claim.wp8r,
                "intake_archive",
                side_effect=AssertionError("unexpected archive intake"),
            ),
            mock.patch.object(
                claim.wp8o,
                "_candidate_report",
                side_effect=AssertionError("unexpected threshold evaluation"),
            ),
        ):
            first = claim.validate(ROOT)
            second = claim.validate(ROOT)
        self.assertEqual(first, second)
        text = first.static_report.decode()
        self.assertIn("approval-status\texplicit-owner-approved\n", text)
        self.assertIn("evidence-status\texact-public-archive-required\n", text)
        self.assertIn("admission-status\tblocked-without-replay\n", text)
        self.assertIn("claim-status\tnot-admitted\n", text)

    def test_coherently_resealed_scope_expansion_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8s-contract-") as name:
            path = Path(name) / "WP8S-CLAIM-ADMISSION.tsv"
            shutil.copy2(
                ROOT / "distribution/s4-performance/WP8S-CLAIM-ADMISSION.tsv",
                path,
            )
            path.write_text(
                path.read_text().replace(
                    "exact-host-commit-bundle-threshold-and-four-kernels-only",
                    "language-wide",
                    1,
                )
            )
            self._reseal(path, claim.CONTRACT_DOMAIN)
            with self.assertRaises(claim.ExactClaimError):
                claim._parse_contract(path)

    def test_claim_or_approval_byte_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="naux-wp8s-approval-") as name:
            copied = Path(name)
            relative_paths = (
                "distribution/s4-performance/WP8S-APPROVED-CLAIM.txt",
                "distribution/s4-performance/WP8S-RELEASE-APPROVAL.md",
            )
            for relative in relative_paths:
                destination = copied / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            for relative in relative_paths:
                with self.subTest(relative=relative):
                    path = copied / relative
                    original = path.read_bytes()
                    path.write_bytes(original + b"drift\n")
                    with self.assertRaises(claim.ExactClaimError):
                        claim._verify_claim_and_approval(copied)
                    path.write_bytes(original)

    def test_authority_rejects_bound_file_drift_and_symlink(self) -> None:
        contract = claim._parse_contract(
            ROOT / "distribution/s4-performance/WP8S-CLAIM-ADMISSION.tsv"
        )
        records, _seal = claim._parse_authority(
            ROOT / "distribution/s4-performance/WP8S-AUTHORITY.tsv", contract
        )
        with tempfile.TemporaryDirectory(prefix="naux-wp8s-files-") as name:
            copied = Path(name)
            for relative in claim.EXPECTED_FILES:
                destination = copied / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            target = copied / "distribution/s4-performance/WP8S-NONCLAIMS.md"
            target.write_bytes(target.read_bytes() + b"drift\n")
            with self.assertRaises(claim.ExactClaimError):
                claim._verify_files(copied, records)
            shutil.copy2(ROOT / "distribution/s4-performance/WP8S-NONCLAIMS.md", target)
            saved = target.with_suffix(".saved")
            target.rename(saved)
            target.symlink_to(saved.name)
            with self.assertRaises(claim.ExactClaimError):
                claim._verify_files(copied, records)

    def test_checker_has_no_network_or_approval_creation_surface(self) -> None:
        source = (ROOT / "scripts/s4_register_residency_exact_claim.py").read_text()
        for token in (
            "import socket",
            "import urllib",
            "import requests",
            "import subprocess",
            "--approve",
            "--claim-text",
            "release edit",
        ):
            self.assertNotIn(token, source)
        self.assertFalse(hasattr(claim, "approve"))
        self.assertFalse(hasattr(claim, "publish"))

    def test_cli_requires_archive_and_receipt_together(self) -> None:
        for arguments in (("--archive", "a"), ("--receipt", "r")):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    claim.main(list(arguments))
            self.assertEqual(raised.exception.code, 2)

    def test_parent_protocol_rejection_emits_no_report(self) -> None:
        output = io.BytesIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                claim.wp8r.wp8q, "validate",
                side_effect=claim.wp8r.wp8q.PublicProtocolError("protocol drift"),
            ),
            mock.patch.object(claim.wp8r, "intake_archive") as intake,
            mock.patch.object(sys, "stdout", buffer=output),
            mock.patch.object(sys, "stderr", stderr),
        ):
            status = claim.main(["--root", str(ROOT)])
        self.assertEqual((status, output.getvalue()), (1, b""))
        self.assertIn("protocol drift", stderr.getvalue())
        intake.assert_not_called()


if __name__ == "__main__":
    unittest.main()
