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
import s4_register_residency_exact_claim as claim


CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == claim.wp8r.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


@unittest.skipUnless(
    CURRENT_APACHE_SURFACE,
    "WP8S replay tests require the Apache-2.0 surface",
)
class RegisterResidencyExactClaimReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="naux-wp8s-replay-")
        self.addCleanup(directory.cleanup)
        self.parent = Path(directory.name)
        self.bundle, evidence, retained = (
            fixture.RegisterResidencyPairedEvidenceReplayTests._bundle(self.parent)
        )
        static = claim.validate(ROOT)
        public = replace(static.public, evidence=evidence)
        threshold = replace(static.threshold, evidence=evidence)
        self.static = replace(static, public=public, threshold=threshold)
        self.patchers = (
            mock.patch.object(claim.wp8r.wp8q, "TRACKED_COMMIT", fixture.COMMIT),
            mock.patch.object(
                claim.wp8r.wp8n.wp8m.wp8k,
                "parse_retained_host",
                return_value=retained,
            ),
        )
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        output = self.parent / "release"
        claim.wp8r.package_bundle(
            ROOT,
            self.bundle,
            claim.EXPECTED.release_tag,
            output,
            public,
        )
        generated_name = claim.wp8r._asset_name(fixture.COMMIT)
        generated_archive = output / generated_name
        generated_receipt = output / f"{generated_name}.receipt.tsv"
        intake = claim.wp8r.intake_archive(generated_archive, generated_receipt, public)
        decisions, _report, threshold_root, passed = claim.wp8o._candidate_report(
            threshold, intake.replay
        )
        self.assertTrue(passed)
        self.assertEqual(len(decisions), 4)
        self.archive = generated_archive
        self.receipt = generated_receipt
        self.expected = replace(
            claim.EXPECTED,
            archive_name=generated_name,
            archive_bytes=self.archive.stat().st_size,
            archive_sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            receipt_name=f"{generated_name}.receipt.tsv",
            receipt_bytes=self.receipt.stat().st_size,
            receipt_sha256=hashlib.sha256(self.receipt.read_bytes()).hexdigest(),
            source_commit=fixture.COMMIT,
            host_attestation=intake.replay.manifest.host_attestation,
            bundle_root=intake.replay.manifest.root,
            session_root=intake.replay.manifest.session_root,
            evidence_root=intake.replay.evidence_root,
            public_intake_root=intake.report_root,
            threshold_root=threshold_root,
        )

    def _admit(self) -> claim.ExactAdmission:
        with mock.patch.object(claim, "EXPECTED", self.expected):
            return claim.admit(self.archive, self.receipt, self.static)

    def test_exact_replay_admits_only_the_approved_observation(self) -> None:
        original = (self.archive.read_bytes(), self.receipt.read_bytes())
        with (
            mock.patch("subprocess.Popen", side_effect=AssertionError("no execution")),
            mock.patch("socket.socket", side_effect=AssertionError("no network")),
        ):
            result = self._admit()
            self.assertEqual(result, self._admit())
        self.assertEqual(original, (self.archive.read_bytes(), self.receipt.read_bytes()))
        text = result.report.decode()
        self.assertEqual(len(result.decisions), 4)
        self.assertTrue(all(item.kernel_pass for item in result.decisions))
        self.assertIn("passing-kernels\t4\n", text)
        self.assertIn("pairs-per-kernel\t30\n", text)
        self.assertIn("claim-status\tadmitted-exact-observation\n", text)
        self.assertIn("approval-signature-status\tnot-a-cryptographic-signature\n", text)

    def test_archive_byte_tampering_fails_before_intake(self) -> None:
        raw = self.archive.read_bytes()
        self.archive.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with (
            mock.patch.object(
                claim.wp8r,
                "intake_archive",
                side_effect=AssertionError("intake after outer hash failure"),
            ),
            mock.patch.object(claim, "EXPECTED", self.expected),
            self.assertRaisesRegex(claim.ExactClaimError, "SHA-256"),
        ):
            claim.admit(self.archive, self.receipt, self.static)

    def test_receipt_tampering_emits_no_admission_on_stdout(self) -> None:
        self.receipt.write_bytes(self.receipt.read_bytes() + b"tamper\n")
        output = io.BytesIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(claim, "EXPECTED", self.expected),
            mock.patch.object(claim, "validate", return_value=self.static),
            mock.patch.object(sys, "stdout", buffer=output),
            mock.patch.object(sys, "stderr", stderr),
        ):
            status = claim.main([
                "--archive", str(self.archive), "--receipt", str(self.receipt),
            ])
        self.assertEqual((status, output.getvalue()), (1, b""))
        self.assertIn("receipt size or SHA-256 drifted", stderr.getvalue())

    def test_any_pinned_identity_drift_fails_closed(self) -> None:
        for field in (
            "bundle_root",
            "session_root",
            "host_attestation",
            "evidence_root",
            "public_intake_root",
            "threshold_root",
        ):
            with self.subTest(field=field), mock.patch.object(
                claim,
                "EXPECTED",
                replace(self.expected, **{field: "0" * 64}),
            ), self.assertRaises(claim.ExactClaimError):
                claim.admit(self.archive, self.receipt, self.static)

    def test_threshold_failure_never_emits_an_admission(self) -> None:
        original = claim.wp8o._candidate_report

        def fail_threshold(admission: object, replay: object) -> tuple[object, bytes, str, bool]:
            decisions, report, root, _passed = original(admission, replay)
            return decisions, report, root, False

        with (
            mock.patch.object(claim, "EXPECTED", self.expected),
            mock.patch.object(claim.wp8o, "_candidate_report", side_effect=fail_threshold),
            self.assertRaisesRegex(claim.ExactClaimError, "did not pass"),
        ):
            claim.admit(self.archive, self.receipt, self.static)


if __name__ == "__main__":
    unittest.main()
