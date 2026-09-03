from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residency_paired_threshold_coq_certificate.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "s4_residency_paired_threshold_coq_certificate_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == bridge.wp8o.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


class S4ResidencyPairedThresholdCoqCertificateTests(unittest.TestCase):
    @unittest.skipUnless(
        CURRENT_APACHE_SURFACE,
        "WP8O certificate test requires the current Apache-2.0 surface",
    )
    def test_exact_static_report_is_authenticated(self) -> None:
        admission = bridge.wp8o.validate(ROOT)
        report = bridge.parse_authenticated_paired_threshold_report(
            admission.static_report, admission
        )
        self.assertEqual(report.report_root, admission.report_root)
        self.assertEqual(
            (
                report.sample_pairs_required,
                report.effective_pairs_required,
                report.sign_alpha_num,
                report.sign_alpha_den,
                report.speedup_num,
                report.speedup_den,
                report.kernels_required,
            ),
            (30, 24, 1, 100, 21, 20, 4),
        )

    @unittest.skipUnless(
        CURRENT_APACHE_SURFACE,
        "WP8O certificate test requires the current Apache-2.0 surface",
    )
    def test_resealed_mode_or_result_drift_is_rejected(self) -> None:
        admission = bridge.wp8o.validate(ROOT)
        for old, new in (
            (
                b"mode\tstatic-no-bundle-no-host-no-clock-no-execution\n",
                b"mode\texplicit-read-only\n",
            ),
            (
                b"threshold-status\tlaw-admitted-result-unavailable\n",
                b"threshold-status\tpass\n",
            ),
        ):
            with self.subTest(old=old):
                body = admission.static_report.rsplit(b"report-root\t", 1)[0]
                body = body.replace(old, new, 1)
                mutated = body + (
                    "report-root\t"
                    + hashlib.sha256(bridge.wp8o.REPORT_DOMAIN + body).hexdigest()
                    + "\n"
                ).encode()
                with self.assertRaisesRegex(
                    bridge.PairedThresholdCertificateError, "metadata drifted"
                ):
                    bridge.parse_authenticated_paired_threshold_report(
                        mutated, admission
                    )

    @unittest.skipUnless(
        CURRENT_APACHE_SURFACE,
        "WP8O certificate test requires the current Apache-2.0 surface",
    )
    def test_resealed_bundle_or_claim_drift_is_rejected(self) -> None:
        admission = bridge.wp8o.validate(ROOT)
        for old, new in (
            (
                b"bundle-status\texternal-eligible-paired-bundle-required\n",
                b"bundle-status\tretained\n",
            ),
            (b"claim-status\tnot-admitted\n", b"claim-status\tadmitted\n"),
        ):
            with self.subTest(old=old):
                body = admission.static_report.rsplit(b"report-root\t", 1)[0]
                body = body.replace(old, new, 1)
                mutated = body + (
                    "report-root\t"
                    + hashlib.sha256(bridge.wp8o.REPORT_DOMAIN + body).hexdigest()
                    + "\n"
                ).encode()
                with self.assertRaisesRegex(
                    bridge.PairedThresholdCertificateError, "metadata drifted"
                ):
                    bridge.parse_authenticated_paired_threshold_report(
                        mutated, admission
                    )

    def test_emitter_exposes_only_the_closed_wp8o_boundary(self) -> None:
        output = bridge.emit_rocq(
            bridge.PairedThresholdReport("a" * 64, 30, 24, 1, 100, 21, 20, 4),
            "b" * 64,
        )
        self.assertIn("GeneratedWP8NPairedEvidence", output)
        self.assertIn("ResidencyPairedThreshold", output)
        self.assertIn("30%nat", output)
        self.assertIn("24%nat", output)
        self.assertIn("100%nat", output)
        self.assertIn("21%nat", output)
        self.assertIn("has_no_candidate", output)
        self.assertIn("is_not_ready", output)
        self.assertIn("has_no_evaluation_authority", output)
        self.assertIn("has_no_performance_claim", output)
        self.assertNotIn("ResidencyPairedThresholdCandidateRetained", output)
        self.assertNotIn("ResidencyRunnerActionPermitted", output)
        self.assertNotIn("ResidencyPerformanceClaimPermitted", output)


if __name__ == "__main__":
    unittest.main()
