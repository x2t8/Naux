from __future__ import annotations

import hashlib
import io
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts.tests import test_s4_register_residency_paired_evidence_replay as fixture


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import s4_review_public_evidence as review


CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == review.wp8r.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE, "Public evidence review requires the Apache-2.0 surface"
)
class PublicEvidenceReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public_admission = review.wp8r.validate(ROOT)
        cls.threshold_admission = review.wp8o.validate(ROOT)

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="naux-public-review-test-")
        self.addCleanup(directory.cleanup)
        self.parent = Path(directory.name)
        self.bundle, evidence, retained = (
            fixture.RegisterResidencyPairedEvidenceReplayTests._bundle(self.parent)
        )
        self.public = replace(self.public_admission, evidence=evidence)
        self.threshold = replace(self.threshold_admission, evidence=evidence)
        for patcher in (
            mock.patch.object(review.wp8r.wp8q, "TRACKED_COMMIT", fixture.COMMIT),
            mock.patch.object(
                review.wp8r.wp8n.wp8m.wp8k,
                "parse_retained_host",
                return_value=retained,
            ),
            mock.patch.object(review.wp8r, "validate", return_value=self.public),
            mock.patch.object(review.wp8o, "validate", return_value=self.threshold),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self._package("passing")

    def _package(self, name: str) -> None:
        output = self.parent / name
        review.wp8r.package_bundle(
            ROOT, self.bundle, "s4-public-review-test", output, self.public
        )
        self.archive = output / review.wp8r._asset_name(fixture.COMMIT)
        self.receipt = output / f"{self.archive.name}.receipt.tsv"

    def _run(self, *extra: str) -> tuple[int, bytes, str]:
        output = io.BytesIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(sys, "stdout", buffer=output),
            mock.patch.object(sys, "stderr", stderr),
        ):
            status = review.main([
                "--root", str(ROOT),
                "--archive", str(self.archive),
                "--receipt", str(self.receipt),
                *extra,
            ])
        return status, output.getvalue(), stderr.getvalue()

    def test_real_archive_replay_preserves_both_reports_and_never_admits(self) -> None:
        intake = review.wp8r.intake_archive(self.archive, self.receipt, self.public)
        _, candidate, root, passed = review.wp8o._candidate_report(
            self.threshold, intake.replay
        )
        original = (self.archive.read_bytes(), self.receipt.read_bytes())
        with (
            mock.patch("subprocess.Popen", side_effect=AssertionError("no execution")),
            mock.patch("socket.socket", side_effect=AssertionError("no network")),
        ):
            result = self._run(
                "--expected-bundle-root", intake.replay.manifest.root,
                "--expected-threshold-root", root,
            )
            self.assertEqual(result, self._run())
        status, report, stderr = result
        self.assertTrue(passed)
        self.assertEqual((status, stderr), (0, ""))
        self.assertEqual(report, intake.report + candidate)
        self.assertEqual(report.count(b"claim-status\tnot-admitted\n"), 2)
        self.assertIn(b"public-reachability\tnot-observed\n", report)
        self.assertIn(b"passing-kernels\t4\n", report)
        self.assertEqual(original, (self.archive.read_bytes(), self.receipt.read_bytes()))

    def test_tampered_archive_emits_no_report(self) -> None:
        raw = self.archive.read_bytes()
        self.archive.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        status, report, stderr = self._run()
        self.assertEqual((status, report), (1, b""))
        self.assertIn("failed", stderr)

    def test_wrong_expected_identity_emits_no_report(self) -> None:
        for option in ("--expected-bundle-root", "--expected-threshold-root"):
            with self.subTest(option=option):
                status, report, stderr = self._run(option, "0" * 64)
                self.assertEqual((status, report), (1, b""))
                self.assertIn(option, stderr)

    def test_valid_threshold_failure_returns_two_with_full_reports(self) -> None:
        # Preserve and reseal every sample, but make kernel 01 entirely tied.
        session = self.bundle / "RAW-PAIRED-SESSION.tsv"
        rows = []
        for line in session.read_text().splitlines():
            fields = line.split("\t")
            if fields[:2] == ["sample-run", "01"] and fields[4] == "04":
                fields[5] = str(int(fields[5]) + 100)
                fields[7] = str(int(fields[7]) + 100)
            rows.append("\t".join(fields))
        session.write_text("\n".join(rows) + "\n")
        fixture.RegisterResidencyPairedEvidenceReplayTests._reseal_session_and_manifest(
            self.bundle
        )
        self._package("failing")
        status, report, stderr = self._run()
        self.assertEqual((status, stderr), (2, ""))
        self.assertIn(b"archive-integrity\tverified\n", report)
        self.assertIn(b"passing-kernels\t3\n", report)
        self.assertIn(b"threshold-candidate\tfail\n", report)
        self.assertEqual(report.count(b"claim-status\tnot-admitted\n"), 2)

    def test_missing_receipt_emits_no_report(self) -> None:
        self.receipt.unlink()
        status, report, stderr = self._run()
        self.assertEqual((status, report), (1, b""))
        self.assertIn("failed", stderr)

    def test_static_authority_failure_stops_before_intake(self) -> None:
        with (
            mock.patch.object(
                review.wp8o, "validate",
                side_effect=review.wp8o.PairedThresholdError("authority drift"),
            ),
            mock.patch.object(review.wp8r, "intake_archive") as intake,
        ):
            status, report, stderr = self._run()
        self.assertEqual((status, report), (1, b""))
        self.assertIn("authority drift", stderr)
        intake.assert_not_called()

    def test_usage_errors_stop_before_validation(self) -> None:
        cases = (
            [],
            ["--archive", str(self.archive)],
            ["--archive", str(self.archive), "--receipt", str(self.receipt),
             "--expected-threshold-root", "9bb2df95"],
            ["--archive", str(self.archive), "--receipt", str(self.receipt),
             "--expected-bundle-root", "A" * 64],
        )
        for arguments in cases:
            with (
                self.subTest(arguments=arguments),
                mock.patch.object(review.wp8r, "validate") as validate,
                mock.patch.object(sys, "stderr", io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                review.main(arguments)
            self.assertEqual(raised.exception.code, 2)
            validate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
