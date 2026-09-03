from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residency_paired_evidence_coq_certificate.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "s4_residency_paired_evidence_coq_certificate_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == bridge.wp8n.wp8m.wp8k.lt1.APACHE_HASH
)


class S4ResidencyPairedEvidenceCoqCertificateTests(unittest.TestCase):
    @unittest.skipUnless(
        CURRENT_APACHE_SURFACE,
        "WP8N certificate test requires the current Apache-2.0 surface",
    )
    def test_exact_static_report_is_authenticated(self) -> None:
        admission = bridge.wp8n.validate(ROOT)
        evidence = bridge.parse_authenticated_paired_evidence_report(
            admission.static_report, admission
        )
        self.assertEqual(evidence.report_root, admission.report_root)
        self.assertEqual(
            (
                evidence.payload_files_required,
                evidence.kernels_required,
                evidence.pairs_per_kernel,
                evidence.pairs_required,
                evidence.invocations_required,
            ),
            (12, 4, 30, 120, 240),
        )

    @unittest.skipUnless(
        CURRENT_APACHE_SURFACE,
        "WP8N certificate test requires the current Apache-2.0 surface",
    )
    def test_resealed_replay_mode_drift_is_rejected(self) -> None:
        admission = bridge.wp8n.validate(ROOT)
        body = admission.static_report.rsplit(b"report-root\t", 1)[0].replace(
            b"mode\tstatic-no-bundle-no-host-no-clock-no-execution\n",
            b"mode\texplicit-read-only\n",
            1,
        )
        mutated = body + (
            "report-root\t"
            + hashlib.sha256(bridge.wp8n.REPORT_DOMAIN + body).hexdigest()
            + "\n"
        ).encode()
        with self.assertRaisesRegex(
            bridge.PairedEvidenceCertificateError, "metadata drifted"
        ):
            bridge.parse_authenticated_paired_evidence_report(mutated, admission)

    @unittest.skipUnless(
        CURRENT_APACHE_SURFACE,
        "WP8N certificate test requires the current Apache-2.0 surface",
    )
    def test_resealed_bundle_or_claim_drift_is_rejected(self) -> None:
        admission = bridge.wp8n.validate(ROOT)
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
                    + hashlib.sha256(bridge.wp8n.REPORT_DOMAIN + body).hexdigest()
                    + "\n"
                ).encode()
                with self.assertRaisesRegex(
                    bridge.PairedEvidenceCertificateError, "metadata drifted"
                ):
                    bridge.parse_authenticated_paired_evidence_report(
                        mutated, admission
                    )

    def test_emitter_exposes_only_the_closed_wp8n_boundary(self) -> None:
        output = bridge.emit_rocq(
            bridge.PairedEvidenceReport("a" * 64, 12, 4, 30, 120, 240),
            "b" * 64,
        )
        self.assertIn("GeneratedWP8MPairedRunner", output)
        self.assertIn("ResidencyPairedEvidenceReplay", output)
        self.assertIn("wp8m_static_paired_runner", output)
        self.assertIn("has_exact_cardinality", output)
        self.assertIn("has_no_bundle", output)
        self.assertIn("is_not_ready", output)
        self.assertIn("has_no_replay_authority", output)
        self.assertIn("has_no_performance_claim", output)
        self.assertNotIn("ResidencyPairedEvidenceBundleRetained", output)
        self.assertNotIn("ResidencyRunnerActionPermitted", output)
        self.assertNotIn("ResidencyPerformanceClaimPermitted", output)


if __name__ == "__main__":
    unittest.main()
