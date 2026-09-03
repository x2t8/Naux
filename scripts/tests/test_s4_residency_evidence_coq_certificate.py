from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/s4_residency_evidence_coq_certificate.py"
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "s4_residency_evidence_coq_certificate_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)

CURRENT_APACHE_SURFACE = (
    hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    == bridge.wp8l.wp8k.lt1.APACHE_HASH
)


class S4ResidencyEvidenceCoqCertificateTests(unittest.TestCase):
    @unittest.skipUnless(
        CURRENT_APACHE_SURFACE,
        "WP8L certificate test requires the current Apache-2.0 surface",
    )
    def test_exact_static_evidence_report_is_authenticated(self) -> None:
        admission = bridge.wp8l.validate(ROOT)
        evidence = bridge.parse_authenticated_evidence_report(
            admission.static_report, admission
        )
        self.assertEqual(evidence.report_root, admission.report_root)
        self.assertEqual(
            (
                evidence.payload_files_required,
                evidence.kernels_required,
                evidence.samples_per_kernel,
                evidence.samples_required,
            ),
            (8, 4, 30, 120),
        )

    @unittest.skipUnless(
        CURRENT_APACHE_SURFACE,
        "WP8L certificate test requires the current Apache-2.0 surface",
    )
    def test_resealed_replay_mode_drift_is_rejected(self) -> None:
        admission = bridge.wp8l.validate(ROOT)
        body = admission.static_report.rsplit(b"report-root\t", 1)[0].replace(
            b"mode\tstatic-no-bundle-no-host-no-clock-no-execution\n",
            b"mode\texplicit-read-only\n",
            1,
        )
        mutated = body + (
            "report-root\t"
            + hashlib.sha256(bridge.wp8l.REPORT_DOMAIN + body).hexdigest()
            + "\n"
        ).encode()
        with self.assertRaisesRegex(
            bridge.EvidenceCertificateError, "metadata drifted"
        ):
            bridge.parse_authenticated_evidence_report(mutated, admission)

    @unittest.skipUnless(
        CURRENT_APACHE_SURFACE,
        "WP8L certificate test requires the current Apache-2.0 surface",
    )
    def test_resealed_claim_drift_is_rejected(self) -> None:
        admission = bridge.wp8l.validate(ROOT)
        body = admission.static_report.rsplit(b"report-root\t", 1)[0].replace(
            b"claim-status\tnot-admitted\n",
            b"claim-status\tadmitted\n",
            1,
        )
        mutated = body + (
            "report-root\t"
            + hashlib.sha256(bridge.wp8l.REPORT_DOMAIN + body).hexdigest()
            + "\n"
        ).encode()
        with self.assertRaisesRegex(
            bridge.EvidenceCertificateError, "metadata drifted"
        ):
            bridge.parse_authenticated_evidence_report(mutated, admission)

    def test_emitter_exposes_only_the_closed_wp8l_boundary(self) -> None:
        output = bridge.emit_rocq(
            bridge.EvidenceReport("a" * 64, 8, 4, 30, 120), "b" * 64
        )
        self.assertIn("GeneratedWP8KRunner", output)
        self.assertIn("ResidencyEvidenceReplay", output)
        self.assertIn("wp8k_static_runner", output)
        self.assertIn("wp8l_static_evidence_replay_is_admitted", output)
        self.assertIn("has_no_bundle", output)
        self.assertIn("is_not_ready", output)
        self.assertIn("has_no_execution_authority", output)
        self.assertIn("has_no_mutation_authority", output)
        self.assertIn("has_no_performance_claim", output)
        self.assertNotIn("ResidencyEvidenceBundleRetained", output)
        self.assertNotIn("ResidencyRunnerActionPermitted", output)
        self.assertNotIn("ResidencyPerformanceClaimPermitted", output)


if __name__ == "__main__":
    unittest.main()
